from __future__ import annotations

import os
import re
import threading
import time
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


@dataclass(frozen=True)
class KeywordSpec:
    key_id: str
    category: str
    label: str
    output_file: str


@dataclass(frozen=True)
class MatchPlan:
    specs: tuple[KeywordSpec, ...]
    subdomain_pairs: tuple[tuple[str, bytes], ...]
    path_pairs: tuple[tuple[str, bytes], ...]
    username_pairs: tuple[tuple[str, bytes], ...]
    port_regex: Optional[re.Pattern[bytes]]
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
                "keyword_counts": dict(self.keyword_counts),
                "errors": list(self.errors),
                "started_at": self.started_at,
                "finished_at": ended,
                "elapsed_seconds": max(elapsed, 0.000001),
            }


class OutputManager:
    def __init__(self, output_root: Path, specs: tuple[KeywordSpec, ...]) -> None:
        self._handles: dict[str, object] = {}
        self._locks: dict[str, threading.Lock] = {}
        for spec in specs:
            category_dir = output_root / spec.category
            category_dir.mkdir(parents=True, exist_ok=True)
            output_path = category_dir / spec.output_file
            handle = open(output_path, "ab", buffering=0)
            self._handles[spec.key_id] = handle
            self._locks[spec.key_id] = threading.Lock()

    def write_batch(self, data: dict[str, bytearray]) -> None:
        for key_id, payload in data.items():
            if not payload:
                continue
            handle = self._handles.get(key_id)
            lock = self._locks.get(key_id)
            if handle is None or lock is None:
                continue
            with lock:
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
    sub_pairs: list[tuple[str, bytes]] = []
    path_pairs: list[tuple[str, bytes]] = []
    user_pairs: list[tuple[str, bytes]] = []
    port_lookup: dict[bytes, str] = {}
    used_sub: set[str] = set()
    used_paths: set[str] = set()
    used_ports: set[str] = set()
    used_users: set[str] = set()

    for keyword in subdomains:
        token = keyword.replace("*", "").strip()
        if not token:
            continue
        stem = unique_name(slugify(keyword), used_sub)
        key_id = f"subdomains:{stem}"
        spec = KeywordSpec(key_id=key_id, category="subdomains", label=keyword, output_file=f"{stem}.txt")
        specs.append(spec)
        sub_pairs.append((key_id, token.encode("utf-8", errors="ignore")))

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

    port_regex = None
    if port_lookup:
        alternates = b"|".join(re.escape(part) for part in sorted(port_lookup.keys(), key=len, reverse=True))
        port_regex = re.compile(rb"(?<!\d):(" + alternates + rb")(?!\d)")

    return MatchPlan(
        specs=tuple(specs),
        subdomain_pairs=tuple(sub_pairs),
        path_pairs=tuple(path_pairs),
        username_pairs=tuple(user_pairs),
        port_regex=port_regex,
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


def process_file(
    file_path: str,
    match_plan: MatchPlan,
    output_manager: OutputManager,
    stats: ScanStats,
    stop_event: threading.Event,
    flush_threshold_bytes: int = 2 * 1024 * 1024,
    progress_interval_bytes: int = 8 * 1024 * 1024,
) -> None:
    buffers: dict[str, bytearray] = defaultdict(bytearray)
    keyword_counts: dict[str, int] = defaultdict(int)
    buffered_output_bytes = 0
    matched_lines_delta = 0
    scanned_bytes_delta = 0
    scanned_lines_delta = 0

    subdomains = match_plan.subdomain_pairs
    paths = match_plan.path_pairs
    usernames = match_plan.username_pairs
    port_regex = match_plan.port_regex
    port_lookup = match_plan.port_lookup

    try:
        with open(file_path, "rb", buffering=4 * 1024 * 1024) as handle:
            for raw_line in handle:
                if stop_event.is_set():
                    break

                line_size = len(raw_line)
                scanned_bytes_delta += line_size
                scanned_lines_delta += 1
                lower_line = raw_line.lower()
                matched_keys: list[str] = []

                for key_id, token in subdomains:
                    if token in lower_line:
                        matched_keys.append(key_id)

                for key_id, token in paths:
                    if token in lower_line:
                        matched_keys.append(key_id)

                for key_id, token in usernames:
                    if token in lower_line:
                        matched_keys.append(key_id)

                if port_regex is not None:
                    seen_ports: set[str] = set()
                    for match in port_regex.finditer(lower_line):
                        key_id = port_lookup.get(match.group(1))
                        if key_id and key_id not in seen_ports:
                            matched_keys.append(key_id)
                            seen_ports.add(key_id)

                if matched_keys:
                    matched_lines_delta += 1
                    for key_id in matched_keys:
                        buffers[key_id].extend(raw_line)
                        keyword_counts[key_id] += 1
                    buffered_output_bytes += line_size * len(matched_keys)

                if buffered_output_bytes >= flush_threshold_bytes:
                    output_manager.write_batch(buffers)
                    stats.add_matches(dict(keyword_counts), matched_lines_delta)
                    buffers.clear()
                    keyword_counts.clear()
                    buffered_output_bytes = 0
                    matched_lines_delta = 0

                if scanned_bytes_delta >= progress_interval_bytes:
                    stats.add_scan(scanned_bytes_delta, scanned_lines_delta)
                    scanned_bytes_delta = 0
                    scanned_lines_delta = 0
    finally:
        if buffers:
            output_manager.write_batch(buffers)
        if keyword_counts or matched_lines_delta:
            stats.add_matches(dict(keyword_counts), matched_lines_delta)
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
        f"lines_scanned: {snapshot['scanned_lines']}",
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

