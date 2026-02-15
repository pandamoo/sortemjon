import tempfile
import threading
import unittest
from pathlib import Path

import ulp_sorter_engine as eng


def _run_scan(lines: list[bytes], workers: int = 1):
    tmp = Path(tempfile.mkdtemp(prefix="ulp_sorter_tests_"))
    logs = tmp / "logs"
    logs.mkdir()
    (logs / "test.log").write_bytes(b"".join(lines))

    plan = eng.build_match_plan(custom_subdomains="", custom_paths="", custom_ports="", custom_usernames="")
    out = logs / "out"
    stop = threading.Event()
    stats = eng.ScanStats(total_files=0, total_bytes=0, specs=plan.specs)
    snap = eng.run_scan(logs_dir=logs, output_dir=out, plan=plan, workers=workers, stop_event=stop, stats=stats)
    return snap, plan, out


class TestEngine(unittest.TestCase):
    def test_is_local_ip_or_host(self):
        self.assertTrue(eng.is_local_ip_or_host(b"127.0.0.1"))
        self.assertTrue(eng.is_local_ip_or_host(b"10.0.0.1"))
        self.assertTrue(eng.is_local_ip_or_host(b"192.168.1.2"))
        self.assertTrue(eng.is_local_ip_or_host(b"172.16.0.5"))
        self.assertTrue(eng.is_local_ip_or_host(b"172.31.255.255"))
        self.assertTrue(eng.is_local_ip_or_host(b"169.254.10.20"))
        self.assertTrue(eng.is_local_ip_or_host(b"100.64.0.1"))
        self.assertTrue(eng.is_local_ip_or_host(b"localhost"))

        self.assertFalse(eng.is_local_ip_or_host(b"8.8.8.8"))
        self.assertFalse(eng.is_local_ip_or_host(b"1.1.1.1"))
        self.assertFalse(eng.is_local_ip_or_host(b"example.com"))

    def test_skip_not_saved_and_local_ip(self):
        lines = [
            b"https://mail.example.com/owa/auth/logon.aspx:john:[NOT_SAVED] trailing\n",
            b"https://192.168.1.10:2083/:admin:pass\n",
            b"https://example.com/adminer.php:admin:pass\n",
        ]
        snap, plan, _ = _run_scan(lines)
        self.assertEqual(snap["scanned_lines"], 3)
        self.assertEqual(snap["skipped_not_saved"], 1)
        self.assertEqual(snap["skipped_local_ip"], 1)
        # Only the public IP/domain line should be eligible for matching.
        self.assertGreaterEqual(snap["matched_lines"], 1)
        self.assertGreaterEqual(snap["total_hits"], 1)

        # Sanity: parsed records include the local-ip and not-saved ones (they parsed, but were skipped).
        self.assertEqual(snap["parsed_ulp_records"], 3)
        self.assertEqual(snap["ignored_non_ulp_lines"], 0)

        # Ensure the admin username key got at least one hit from the public domain line.
        admin_spec = next(spec for spec in plan.specs if spec.category == "usernames" and spec.label == "admin")
        self.assertGreaterEqual(snap["keyword_counts"].get(admin_spec.key_id, 0), 1)

    def test_subdomain_wildcard_boundary(self):
        lines = [
            b"https://mail.example.com/:u:p\n",
            b"https://mailbox.example.com/:u:p\n",
            b"https://mail/:u:p\n",
        ]
        snap, plan, _ = _run_scan(lines)
        mail_spec = next(spec for spec in plan.specs if spec.category == "subdomains" and spec.label == "mail.*")
        self.assertEqual(snap["keyword_counts"].get(mail_spec.key_id, 0), 2)

    def test_oversized_line_is_skipped(self):
        big = b"A" * (eng.DEFAULT_MAX_LINE_BYTES + 500) + b"\n"
        lines = [
            big,
            b"https://guacamole.example.com/guacamole/:admin:pass\n",
        ]
        snap, _, _ = _run_scan(lines)
        self.assertEqual(snap["skipped_oversized_lines"], 1)
        self.assertEqual(snap["parsed_ulp_records"], 1)
        self.assertEqual(snap["ignored_non_ulp_lines"], 0)


if __name__ == "__main__":
    unittest.main()

