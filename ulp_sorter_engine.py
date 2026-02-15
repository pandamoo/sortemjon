from __future__ import annotations

import os
import re
import threading
import time
import errno
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

DEFAULT_SUBDOMAINS = (
    "guacamole.*",
    "mail.*",
    "webmail.*",
    "cpanel.*",
    "metabase.*",
    "gitlab.*",
    "rdweb.*",
    "smtp.*",
)

DEFAULT_PATHS = (
    "/owa/auth/logon.aspx",
    "/rdweb/",
    "/guacamole/",
    "/adminer2.php",
    "/adminer.php",
)

DEFAULT_PORTS = (
    ":2083",
    "22",
    "21",
    "587",
    "25",
    "465",
)

DEFAULT_USERNAMES = ("admin",)

OUTPUT_PREFIX = "ulp_sorted_output_"

_NOT_SAVED_PASSWORDS = (b"[NOT_SAVED]", b"[not_saved]")
_LOCALHOST_HOSTS = {b"localhost", b"localhost.localdomain"}

# Safety limit: prevents OOM when scanning binary files with no newlines.
DEFAULT_MAX_LINE_BYTES = 1024 * 1024  # 1 MiB


@dataclass(frozen=True)
class KeywordSpec:
    key_id: str
    category: str
    label: str
    output_file: str


@dataclass(frozen=True)
class MatchPlan:
    specs: tuple[KeywordSpec, ...]
    subdomain_prefix_pairs: tuple[tuple[str, bytes], ...]
    subdomain_contains_pairs: tuple[tuple[str, bytes], ...]
    path_pairs: tuple[tuple[str, bytes], ...]
    username_pairs: tuple[tuple[str, bytes], ...]
    port_lookup: dict[bytes, str]


class ScanStats:
    def __init__(self, total_files: int, total_bytes: int, specs: tuple[KeywordSpec, ...]) -> None:
        self.lock = threading.Lock()
        self.total_files = total_files
        self.total_bytes = total_bytes
        self.processed_files = 0
        self.scanned_bytes = 0
        self.scanned_lines = 0
        self.matched_lines = 0
        self.total_hits = 0
        self.parsed_ulp_records = 0
        self.ignored_non_ulp_lines = 0
        self.skipped_oversized_lines = 0
        self.skipped_not_saved = 0
        self.skipped_local_ip = 0
        self.keyword_counts = {spec.key_id: 0 for spec in specs}
        self.errors: list[str] = []
        self.started_at = time.time()
        self.finished_at: Optional[float] = None

    def set_totals(self, total_files: int, total_bytes: int) -> None:
        with self.lock:
            self.total_files = total_files
            self.total_bytes = total_bytes

    def add_scan(self, byte_count: int, line_count: int) -> None:
        if byte_count == 0 and line_count == 0:
            return
        with self.lock:
            self.scanned_bytes += byte_count
            self.scanned_lines += line_count

    def add_matches(self, keyword_deltas: dict[str, int], matched_lines_delta: int) -> None:
        if not keyword_deltas and matched_lines_delta == 0:
            return
        with self.lock:
            for key_id, amount in keyword_deltas.items():
                self.keyword_counts[key_id] = self.keyword_counts.get(key_id, 0) + amount
                self.total_hits += amount
            self.matched_lines += matched_lines_delta

    def add_skips(self, not_saved_delta: int, local_ip_delta: int) -> None:
        if not_saved_delta == 0 and local_ip_delta == 0:
            return
        with self.lock:
            self.skipped_not_saved += not_saved_delta
            self.skipped_local_ip += local_ip_delta

    def add_ignored(self, parsed_ulp_delta: int, non_ulp_delta: int, oversized_delta: int) -> None:
        if parsed_ulp_delta == 0 and non_ulp_delta == 0 and oversized_delta == 0:
            return
        with self.lock:
            self.parsed_ulp_records += parsed_ulp_delta
            self.ignored_non_ulp_lines += non_ulp_delta
            self.skipped_oversized_lines += oversized_delta

    def mark_file_done(self) -> None:
        with self.lock:
            self.processed_files += 1

    def add_error(self, file_path: str, message: str) -> None:
        with self.lock:
            self.errors.append(f"{file_path}: {message}")

    def finish(self) -> dict:
        with self.lock:
            if self.finished_at is None:
                self.finished_at = time.time()
        return self.snapshot()

    def snapshot(self) -> dict:
        with self.lock:
            ended = self.finished_at
            elapsed = (ended or time.time()) - self.started_at
            return {
                "total_files": self.total_files,
                "total_bytes": self.total_bytes,
                "processed_files": self.processed_files,
                "scanned_bytes": self.scanned_bytes,
                "scanned_lines": self.scanned_lines,
                "matched_lines": self.matched_lines,
                "total_hits": self.total_hits,
                "parsed_ulp_records": self.parsed_ulp_records,
                "ignored_non_ulp_lines": self.ignored_non_ulp_lines,
                "skipped_oversized_lines": self.skipped_oversized_lines,
                "skipped_not_saved": self.skipped_not_saved,
                "skipped_local_ip": self.skipped_local_ip,
                "keyword_counts": dict(self.keyword_counts),
                "errors": list(self.errors),
                "started_at": self.started_at,
                "finished_at": ended,
                "elapsed_seconds": max(elapsed, 0.000001),
            }


class OutputManager:
    def __init__(self, output_root: Path, specs: tuple[KeywordSpec, ...]) -> None:
        self._paths: dict[str, Path] = {}
        self._handles: dict[str, object] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._mode = "preopen"

        for spec in specs:
            category_dir = output_root / spec.category
            category_dir.mkdir(parents=True, exist_ok=True)
            output_path = category_dir / spec.output_file
            self._paths[spec.key_id] = output_path
            self._locks[spec.key_id] = threading.Lock()

        # Fast path: keep all output files open (best throughput).
        try:
            for key_id, output_path in self._paths.items():
                self._handles[key_id] = open(output_path, "ab", buffering=0)
        except OSError as exc:
            # Production hardening: if we exceed the OS fd limit, fall back to opening
            # per write. Slower, but avoids crashing on very large keyword sets.
            if exc.errno == errno.EMFILE:
                self._mode = "open_per_write"
                for handle in self._handles.values():
                    try:
                        handle.close()
                    except OSError:
                        pass
                self._handles.clear()
                # Ensure files exist even if no matches are written.
                for output_path in self._paths.values():
                    with open(output_path, "ab", buffering=0):
                        pass
            else:
                raise

    def write_batch(self, data: dict[str, bytearray]) -> None:
        if self._mode == "preopen":
            for key_id, payload in data.items():
                if not payload:
                    continue
                handle = self._handles.get(key_id)
                lock = self._locks.get(key_id)
                if handle is None or lock is None:
                    continue
                with lock:
                    handle.write(payload)
            return

        # Fallback mode (EMFILE-safe): open -> write -> close for each flush.
        for key_id, payload in data.items():
            if not payload:
                continue
            output_path = self._paths.get(key_id)
            lock = self._locks.get(key_id)
            if output_path is None or lock is None:
                continue
            with lock:
                with open(output_path, "ab", buffering=0) as handle:
                    handle.write(payload)

    def close(self) -> None:
        for handle in self._handles.values():
            try:
                handle.close()
            except OSError:
                pass


def parse_keywords(raw_text: str) -> list[str]:
    if not raw_text.strip():
        return []
    return [chunk for chunk in re.split(r"[\s,;]+", raw_text.strip()) if chunk]


def normalize_subdomain(value: str) -> str:
    return value.strip().lower()


def normalize_path(value: str) -> str:
    return value.strip().lower()


def normalize_username(value: str) -> str:
    return value.strip().lower()


def normalize_port(value: str) -> str:
    cleaned = value.strip().lower()
    if cleaned.startswith(":"):
        cleaned = cleaned[1:]
    if not cleaned.isdigit():
        return ""
    return cleaned


def dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def slugify(value: str) -> str:
    lower = value.lower().strip()
    lower = lower.replace("*", "star")
    lower = lower.replace(":", "")
    lower = lower.replace(".", "_")
    lower = lower.replace("/", "_")
    lower = re.sub(r"[^a-z0-9._-]+", "_", lower)
    lower = re.sub(r"_+", "_", lower).strip("_.-")
    return lower or "keyword"


def unique_name(base: str, used: set[str]) -> str:
    candidate = base
    index = 2
    while candidate in used:
        candidate = f"{base}_{index}"
        index += 1
    used.add(candidate)
    return candidate


def build_match_plan(
    custom_subdomains: str,
    custom_paths: str,
    custom_ports: str,
    custom_usernames: str,
) -> MatchPlan:
    subdomains = dedupe(
        [normalize_subdomain(value) for value in [*DEFAULT_SUBDOMAINS, *parse_keywords(custom_subdomains)]]
    )
    paths = dedupe([normalize_path(value) for value in [*DEFAULT_PATHS, *parse_keywords(custom_paths)]])
    users = dedupe(
        [normalize_username(value) for value in [*DEFAULT_USERNAMES, *parse_keywords(custom_usernames)]]
    )
    ports = dedupe(
        [normalize_port(value) for value in [*DEFAULT_PORTS, *parse_keywords(custom_ports)] if normalize_port(value)]
    )

    specs: list[KeywordSpec] = []
    sub_prefix_pairs: list[tuple[str, bytes]] = []
    sub_contains_pairs: list[tuple[str, bytes]] = []
    path_pairs: list[tuple[str, bytes]] = []
    user_pairs: list[tuple[str, bytes]] = []
    port_lookup: dict[bytes, str] = {}
    used_sub: set[str] = set()
    used_paths: set[str] = set()
    used_ports: set[str] = set()
    used_users: set[str] = set()

    for keyword in subdomains:
        cleaned = keyword.strip()
        if not cleaned:
            continue
        stem = unique_name(slugify(keyword), used_sub)
        key_id = f"subdomains:{stem}"
        spec = KeywordSpec(key_id=key_id, category="subdomains", label=keyword, output_file=f"{stem}.txt")
        specs.append(spec)
        # Most subdomain patterns are like "mail.*" => match host label boundary:
        # - "mail" or "mail.example.com"
        # (not "mailbox.example.com")
        if cleaned.endswith(".*") and cleaned.count("*") == 1:
            base = cleaned[:-2].strip().strip(".")
            if base:
                sub_prefix_pairs.append((key_id, base.encode("utf-8", errors="ignore")))
        else:
            token = cleaned.replace("*", "").strip()
            if token:
                sub_contains_pairs.append((key_id, token.encode("utf-8", errors="ignore")))

    for keyword in paths:
        if not keyword:
            continue
        stem = unique_name(slugify(keyword), used_paths)
        key_id = f"paths:{stem}"
        spec = KeywordSpec(key_id=key_id, category="paths", label=keyword, output_file=f"{stem}.txt")
        specs.append(spec)
        path_pairs.append((key_id, keyword.encode("utf-8", errors="ignore")))

    for port in ports:
        label = f":{port}"
        stem = unique_name(f"port_{port}", used_ports)
        key_id = f"ports:{stem}"
        spec = KeywordSpec(key_id=key_id, category="ports", label=label, output_file=f"{stem}.txt")
        specs.append(spec)
        port_lookup[port.encode()] = key_id

    for username in users:
        if not username:
            continue
        stem = unique_name(slugify(username), used_users)
        key_id = f"usernames:{stem}"
        spec = KeywordSpec(key_id=key_id, category="usernames", label=username, output_file=f"{stem}.txt")
        specs.append(spec)
        user_pairs.append((key_id, username.encode("utf-8", errors="ignore")))

    return MatchPlan(
        specs=tuple(specs),
        subdomain_prefix_pairs=tuple(sub_prefix_pairs),
        subdomain_contains_pairs=tuple(sub_contains_pairs),
        path_pairs=tuple(path_pairs),
        username_pairs=tuple(user_pairs),
        port_lookup=port_lookup,
    )


def discover_files(root_dir: Path) -> list[tuple[str, int]]:
    stack = [root_dir]
    files: list[tuple[str, int]] = []

    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name.startswith(OUTPUT_PREFIX):
                                continue
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            stat = entry.stat(follow_symlinks=False)
                            files.append((entry.path, stat.st_size))
                    except OSError:
                        continue
        except OSError:
            continue

    files.sort(key=lambda item: item[1], reverse=True)
    return files


def is_local_ip_or_host(host_lower: bytes) -> bool:
    # Local hostnames
    if not host_lower:
        return False
    if host_lower in _LOCALHOST_HOSTS:
        return True

    # IPv4 fast-path (common in logs)
    first = host_lower[0]
    if 48 <= first <= 57 and host_lower.count(b".") == 3:
        parts = host_lower.split(b".")
        if len(parts) == 4:
            try:
                a = int(parts[0])
                b = int(parts[1])
                c = int(parts[2])
                d = int(parts[3])
            except ValueError:
                return False
            if not (0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 255 and 0 <= d <= 255):
                return False
            # RFC1918 / local / loopback / link-local / CGNAT
            if a in (0, 10, 127):
                return True
            if a == 169 and b == 254:
                return True
            if a == 172 and 16 <= b <= 31:
                return True
            if a == 192 and b == 168:
                return True
            if a == 100 and 64 <= b <= 127:
                return True
        return False

    # IPv6 (rare). Only attempt parsing when ':' is present.
    if b":" in host_lower:
        try:
            import ipaddress

            ip = ipaddress.ip_address(host_lower.decode("ascii", errors="ignore"))
        except Exception:
            return False
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

    return False


def process_file(
    file_path: str,
    match_plan: MatchPlan,
    output_manager: OutputManager,
    stats: ScanStats,
    stop_event: threading.Event,
    flush_threshold_bytes: int = 2 * 1024 * 1024,
    progress_interval_bytes: int = 8 * 1024 * 1024,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
) -> None:
    buffers: dict[str, bytearray] = defaultdict(bytearray)
    keyword_counts: dict[str, int] = defaultdict(int)
    buffered_output_bytes = 0
    matched_lines_delta = 0
    scanned_bytes_delta = 0
    scanned_lines_delta = 0

    sub_prefixes = match_plan.subdomain_prefix_pairs
    sub_contains = match_plan.subdomain_contains_pairs
    paths = match_plan.path_pairs
    usernames = match_plan.username_pairs
    port_lookup = match_plan.port_lookup
    skipped_not_saved_delta = 0
    skipped_local_ip_delta = 0
    parsed_ulp_delta = 0
    ignored_non_ulp_delta = 0
    oversized_lines_delta = 0

    try:
        with open(file_path, "rb", buffering=4 * 1024 * 1024) as handle:
            # Use bounded readline to avoid OOM on binary files with no newlines.
            while True:
                if stop_event.is_set():
                    break
                raw_line = handle.readline(max_line_bytes + 1)
                if not raw_line:
                    break

                if len(raw_line) > max_line_bytes:
                    oversized_lines_delta += 1
                    # Count the bytes we already read; then drain until newline/EOF.
                    scanned_bytes_delta += len(raw_line)
                    scanned_lines_delta += 1
                    while raw_line and raw_line[-1] != 10 and not stop_event.is_set():
                        raw_line = handle.readline(max_line_bytes + 1)
                        if not raw_line:
                            break
                        scanned_bytes_delta += len(raw_line)
                        # Keep UI/progress responsive even when draining a huge no-newline blob.
                        if scanned_bytes_delta >= progress_interval_bytes:
                            stats.add_scan(scanned_bytes_delta, scanned_lines_delta)
                            stats.add_skips(skipped_not_saved_delta, skipped_local_ip_delta)
                            stats.add_ignored(parsed_ulp_delta, ignored_non_ulp_delta, oversized_lines_delta)
                            scanned_bytes_delta = 0
                            scanned_lines_delta = 0
                            skipped_not_saved_delta = 0
                            skipped_local_ip_delta = 0
                            parsed_ulp_delta = 0
                            ignored_non_ulp_delta = 0
                            oversized_lines_delta = 0
                    continue

                line_size = len(raw_line)
                scanned_bytes_delta += line_size
                scanned_lines_delta += 1
                # Trim newline (keep raw_line for output writes).
                end = line_size
                if end and raw_line[end - 1] == 10:  # \n
                    end -= 1
                if end and raw_line[end - 1] == 13:  # \r
                    end -= 1
                if end <= 0:
                    ignored_non_ulp_delta += 1
                    continue

                # Parse ULP structure: url(:port)(/path):user:pass  (port/path optional)
                last_colon = raw_line.rfind(b":", 0, end)
                if last_colon == -1:
                    ignored_non_ulp_delta += 1
                    continue
                second_last_colon = raw_line.rfind(b":", 0, last_colon)
                if second_last_colon == -1:
                    ignored_non_ulp_delta += 1
                    continue

                # Password field (skip [NOT_SAVED])
                p_start = last_colon + 1
                p_end = end
                while p_start < p_end and raw_line[p_start] <= 32:
                    p_start += 1
                # Only consider the first token of the password field (ignore trailing metadata).
                p_token_end = p_start
                while p_token_end < p_end and raw_line[p_token_end] > 32:
                    p_token_end += 1
                if p_token_end - p_start == 11 and raw_line[p_start] == 91 and raw_line[p_token_end - 1] == 93:  # [...]
                    pw_token = raw_line[p_start:p_token_end]
                    if pw_token in _NOT_SAVED_PASSWORDS or pw_token.upper() == b"[NOT_SAVED]":
                        # Count it as a recognized ULP record even though we skip it
                        # before parsing the URL/host for speed.
                        parsed_ulp_delta += 1
                        skipped_not_saved_delta += 1
                        continue

                # Username field
                u_start = second_last_colon + 1
                u_end = last_colon
                while u_start < u_end and raw_line[u_start] <= 32:
                    u_start += 1
                while u_end > u_start and raw_line[u_end - 1] <= 32:
                    u_end -= 1
                if u_end <= u_start:
                    ignored_non_ulp_delta += 1
                    continue
                # Only take the first token of username (ignore trailing metadata).
                u_token_end = u_start
                while u_token_end < u_end and raw_line[u_token_end] > 32:
                    u_token_end += 1
                if u_token_end <= u_start:
                    ignored_non_ulp_delta += 1
                    continue
                user_lower = raw_line[u_start:u_token_end].lower()

                # URL field
                url_start = 0
                url_end = second_last_colon
                while url_start < url_end and raw_line[url_start] <= 32:
                    url_start += 1
                while url_end > url_start and raw_line[url_end - 1] <= 32:
                    url_end -= 1
                if url_end <= url_start:
                    ignored_non_ulp_delta += 1
                    continue

                scheme = raw_line.find(b"://", url_start, url_end)
                host_start = scheme + 3 if scheme != -1 else url_start
                if raw_line.startswith(b"//", url_start):
                    host_start = url_start + 2

                slash = raw_line.find(b"/", host_start, url_end)
                if slash == -1:
                    hostport_start = host_start
                    hostport_end = url_end
                    path_lower = b""
                else:
                    hostport_start = host_start
                    hostport_end = slash
                    path_lower = raw_line[slash:url_end].lower()

                while hostport_start < hostport_end and raw_line[hostport_start] <= 32:
                    hostport_start += 1
                while hostport_end > hostport_start and raw_line[hostport_end - 1] <= 32:
                    hostport_end -= 1
                if hostport_end <= hostport_start:
                    ignored_non_ulp_delta += 1
                    continue

                port_bytes: Optional[bytes] = None

                if raw_line[hostport_start] == 91:  # '['
                    bracket_end = raw_line.find(b"]", hostport_start + 1, hostport_end)
                    if bracket_end == -1:
                        continue
                    host_raw = raw_line[hostport_start + 1 : bracket_end]
                    rest_start = bracket_end + 1
                    if rest_start < hostport_end and raw_line[rest_start] == 58:  # ':'
                        pp_start = rest_start + 1
                        pp_end = hostport_end
                        while pp_start < pp_end and raw_line[pp_start] <= 32:
                            pp_start += 1
                        while pp_end > pp_start and raw_line[pp_end - 1] <= 32:
                            pp_end -= 1
                        if pp_end > pp_start:
                            candidate = raw_line[pp_start:pp_end]
                            if candidate.isdigit():
                                port_bytes = candidate
                    host_lower = host_raw.lower()
                else:
                    colon = raw_line.rfind(b":", hostport_start, hostport_end)
                    if colon != -1:
                        pp_start = colon + 1
                        pp_end = hostport_end
                        while pp_start < pp_end and raw_line[pp_start] <= 32:
                            pp_start += 1
                        while pp_end > pp_start and raw_line[pp_end - 1] <= 32:
                            pp_end -= 1
                        candidate = raw_line[pp_start:pp_end]
                        if candidate.isdigit():
                            port_bytes = candidate
                            host_end = colon
                        else:
                            host_end = hostport_end
                    else:
                        host_end = hostport_end

                    h_start = hostport_start
                    h_end = host_end
                    while h_start < h_end and raw_line[h_start] <= 32:
                        h_start += 1
                    while h_end > h_start and raw_line[h_end - 1] <= 32:
                        h_end -= 1
                    while h_end > h_start and raw_line[h_end - 1] == 46:  # '.'
                        h_end -= 1
                    if h_end <= h_start:
                        ignored_non_ulp_delta += 1
                        continue
                    host_lower = raw_line[h_start:h_end].lower()

                parsed_ulp_delta += 1

                if is_local_ip_or_host(host_lower):
                    skipped_local_ip_delta += 1
                    continue

                matched_keys: list[str] = []

                for key_id, prefix in sub_prefixes:
                    # "mail.*" should match "mail" and "mail.example.com", but not "mailbox.example.com"
                    if host_lower == prefix or host_lower.startswith(prefix + b"."):
                        matched_keys.append(key_id)

                for key_id, token in sub_contains:
                    if token in host_lower:
                        matched_keys.append(key_id)

                if path_lower:
                    for key_id, token in paths:
                        if token in path_lower:
                            matched_keys.append(key_id)

                for key_id, token in usernames:
                    if token in user_lower:
                        matched_keys.append(key_id)

                if port_bytes is not None:
                    port_key_id = port_lookup.get(port_bytes)
                    if port_key_id:
                        matched_keys.append(port_key_id)

                if matched_keys:
                    matched_lines_delta += 1
                    for key_id in matched_keys:
                        buffers[key_id].extend(raw_line)
                        keyword_counts[key_id] += 1
                    buffered_output_bytes += line_size * len(matched_keys)

                if buffered_output_bytes >= flush_threshold_bytes:
                    output_manager.write_batch(buffers)
                    stats.add_matches(dict(keyword_counts), matched_lines_delta)
                    stats.add_skips(skipped_not_saved_delta, skipped_local_ip_delta)
                    stats.add_ignored(parsed_ulp_delta, ignored_non_ulp_delta, oversized_lines_delta)
                    buffers.clear()
                    keyword_counts.clear()
                    buffered_output_bytes = 0
                    matched_lines_delta = 0
                    skipped_not_saved_delta = 0
                    skipped_local_ip_delta = 0
                    parsed_ulp_delta = 0
                    ignored_non_ulp_delta = 0
                    oversized_lines_delta = 0

                if scanned_bytes_delta >= progress_interval_bytes:
                    stats.add_scan(scanned_bytes_delta, scanned_lines_delta)
                    stats.add_skips(skipped_not_saved_delta, skipped_local_ip_delta)
                    stats.add_ignored(parsed_ulp_delta, ignored_non_ulp_delta, oversized_lines_delta)
                    scanned_bytes_delta = 0
                    scanned_lines_delta = 0
                    skipped_not_saved_delta = 0
                    skipped_local_ip_delta = 0
                    parsed_ulp_delta = 0
                    ignored_non_ulp_delta = 0
                    oversized_lines_delta = 0
    finally:
        if buffers:
            output_manager.write_batch(buffers)
        if keyword_counts or matched_lines_delta:
            stats.add_matches(dict(keyword_counts), matched_lines_delta)
        if skipped_not_saved_delta or skipped_local_ip_delta:
            stats.add_skips(skipped_not_saved_delta, skipped_local_ip_delta)
        if parsed_ulp_delta or ignored_non_ulp_delta or oversized_lines_delta:
            stats.add_ignored(parsed_ulp_delta, ignored_non_ulp_delta, oversized_lines_delta)
        if scanned_bytes_delta or scanned_lines_delta:
            stats.add_scan(scanned_bytes_delta, scanned_lines_delta)
        stats.mark_file_done()


def format_bytes(byte_count: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(byte_count)
    idx = 0
    while value >= 1024.0 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    return f"{value:.2f} {units[idx]}"


def format_rate(byte_count: float) -> str:
    if byte_count <= 0:
        return "0 B/s"
    return f"{format_bytes(int(byte_count))}/s"


def write_summary_file(output_dir: Path, snapshot: dict, plan: MatchPlan, cancelled: bool) -> None:
    started = datetime.fromtimestamp(snapshot["started_at"]).isoformat(sep=" ", timespec="seconds")
    finished_at = snapshot["finished_at"] or time.time()
    ended = datetime.fromtimestamp(finished_at).isoformat(sep=" ", timespec="seconds")

    lines = [
        f"started: {started}",
        f"finished: {ended}",
        f"cancelled: {'yes' if cancelled else 'no'}",
        f"files_processed: {snapshot['processed_files']}/{snapshot['total_files']}",
        f"bytes_scanned: {snapshot['scanned_bytes']}",
        f"bytes_scanned_human: {format_bytes(snapshot['scanned_bytes'])}",
        f"lines_scanned: {snapshot['scanned_lines']}",
        f"parsed_ulp_records: {snapshot.get('parsed_ulp_records', 0)}",
        f"ignored_non_ulp_lines: {snapshot.get('ignored_non_ulp_lines', 0)}",
        f"skipped_oversized_lines: {snapshot.get('skipped_oversized_lines', 0)}",
        f"skipped_not_saved: {snapshot.get('skipped_not_saved', 0)}",
        f"skipped_local_ip: {snapshot.get('skipped_local_ip', 0)}",
        f"matched_lines: {snapshot['matched_lines']}",
        f"total_hits: {snapshot['total_hits']}",
        "",
        "keyword_hits:",
    ]

    keyword_counts: dict[str, int] = snapshot["keyword_counts"]
    for spec in plan.specs:
        count = keyword_counts.get(spec.key_id, 0)
        lines.append(f"{spec.category}/{spec.output_file}\t{count}\t{spec.label}")

    if snapshot["errors"]:
        lines.append("")
        lines.append("errors:")
        lines.extend(snapshot["errors"])

    (output_dir / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_scan(
    logs_dir: Path,
    output_dir: Path,
    plan: MatchPlan,
    workers: int,
    stop_event: threading.Event,
    stats: ScanStats,
) -> dict:
    files = discover_files(logs_dir)
    total_files = len(files)
    total_bytes = sum(size for _, size in files)
    stats.set_totals(total_files, total_bytes)

    if total_files == 0:
        return stats.finish()

    output_dir.mkdir(parents=True, exist_ok=True)
    output_manager = OutputManager(output_dir, plan.specs)
    active_workers = min(max(1, workers), total_files)

    try:
        with ThreadPoolExecutor(max_workers=active_workers) as executor:
            futures = {
                executor.submit(process_file, file_path, plan, output_manager, stats, stop_event): file_path
                for file_path, _ in files
            }
            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    stats.add_error(file_path, str(exc))
    finally:
        output_manager.close()

    return stats.finish()

