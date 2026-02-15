#!/usr/bin/env python3
from __future__ import annotations

import os
import queue
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

import ulp_sorter_engine as eng

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    TK_AVAILABLE = True
    TK_IMPORT_ERROR: Optional[BaseException] = None
except ModuleNotFoundError as exc:  # pragma: no cover
    # Tk is optional for importing/testing the engine; required for the GUI.
    TK_AVAILABLE = False
    TK_IMPORT_ERROR = exc


if TK_AVAILABLE:

    class ULPSorterApp(tk.Tk):
        def __init__(self) -> None:
            super().__init__()
            self.title("ULP Sorter")
            self.geometry("1200x820")
            self.minsize(1000, 700)

            self.logs_dir_var = tk.StringVar()
            self.worker_var = tk.IntVar(value=self.default_workers())
            self.status_var = tk.StringVar(value="Idle")
            self.files_var = tk.StringVar(value="Files: 0/0")
            self.bytes_var = tk.StringVar(value="Bytes: 0 B / 0 B")
            self.lines_var = tk.StringVar(value="Lines: 0")
            self.hits_var = tk.StringVar(value="Hits: 0")
            self.skipped_var = tk.StringVar(value="Skipped: 0")
            self.speed_var = tk.StringVar(value="Speed: 0 B/s")
            self.elapsed_var = tk.StringVar(value="Elapsed: 0.0s")

            self.events: queue.Queue[tuple[str, object]] = queue.Queue()
            self.stop_event = threading.Event()
            self.scan_thread: Optional[threading.Thread] = None
            self.current_stats: Optional[eng.ScanStats] = None
            self.current_plan: Optional[eng.MatchPlan] = None
            self.tree_items: dict[str, str] = {}
            self.running = False

            self.custom_subdomains_text: tk.Text
            self.custom_paths_text: tk.Text
            self.custom_ports_text: tk.Text
            self.custom_users_text: tk.Text
            self.progress = ttk.Progressbar(self, mode="determinate", maximum=100)
            self.tree = ttk.Treeview(self, columns=("category", "keyword", "matches"), show="headings")

            self.start_btn: ttk.Button
            self.stop_btn: ttk.Button

            self.build_ui()
            self.after(200, self.refresh_ui)

        @staticmethod
        def default_workers() -> int:
            cpu = os.cpu_count() or 4
            return max(2, min(16, cpu))

        def build_ui(self) -> None:
            main = ttk.Frame(self, padding=12)
            main.pack(fill="both", expand=True)

            source_frame = ttk.LabelFrame(main, text="Log Source")
            source_frame.pack(fill="x")
            source_frame.columnconfigure(1, weight=1)

            ttk.Label(source_frame, text="Logs directory:").grid(row=0, column=0, padx=6, pady=6, sticky="w")
            ttk.Entry(source_frame, textvariable=self.logs_dir_var).grid(
                row=0, column=1, padx=6, pady=6, sticky="ew"
            )
            ttk.Button(source_frame, text="Browse", command=self.browse_logs_dir).grid(
                row=0, column=2, padx=6, pady=6, sticky="ew"
            )
            ttk.Label(source_frame, text="Workers:").grid(row=0, column=3, padx=(20, 6), pady=6, sticky="e")
            ttk.Spinbox(source_frame, from_=1, to=64, textvariable=self.worker_var, width=6).grid(
                row=0, column=4, padx=6, pady=6, sticky="w"
            )

            self.start_btn = ttk.Button(source_frame, text="Start Scan", command=self.start_scan)
            self.start_btn.grid(row=0, column=5, padx=(20, 6), pady=6, sticky="ew")
            self.stop_btn = ttk.Button(source_frame, text="Stop", command=self.stop_scan, state="disabled")
            self.stop_btn.grid(row=0, column=6, padx=6, pady=6, sticky="ew")

            keywords_frame = ttk.Frame(main)
            keywords_frame.pack(fill="x", pady=(10, 0))
            keywords_frame.columnconfigure(0, weight=1)
            keywords_frame.columnconfigure(1, weight=1)

            defaults_frame = ttk.LabelFrame(keywords_frame, text="Base Keyword Set")
            defaults_frame.grid(row=0, column=0, padx=(0, 6), sticky="nsew")
            defaults_text = tk.Text(defaults_frame, height=12, wrap="word")
            defaults_text.pack(fill="both", expand=True, padx=6, pady=6)
            defaults_text.insert(
                "1.0",
                (
                    "Subdomains:\n"
                    + ", ".join(eng.DEFAULT_SUBDOMAINS)
                    + "\n\nPaths:\n"
                    + ", ".join(eng.DEFAULT_PATHS)
                    + "\n\nPorts:\n"
                    + ", ".join(eng.DEFAULT_PORTS)
                    + "\n\nUsernames:\n"
                    + ", ".join(eng.DEFAULT_USERNAMES)
                ),
            )
            defaults_text.configure(state="disabled")

            custom_frame = ttk.LabelFrame(keywords_frame, text="Custom Keywords (comma/space/newline separated)")
            custom_frame.grid(row=0, column=1, padx=(6, 0), sticky="nsew")
            custom_frame.columnconfigure(1, weight=1)

            ttk.Label(custom_frame, text="Subdomains:").grid(row=0, column=0, padx=6, pady=4, sticky="nw")
            self.custom_subdomains_text = tk.Text(custom_frame, height=2)
            self.custom_subdomains_text.grid(row=0, column=1, padx=6, pady=4, sticky="ew")

            ttk.Label(custom_frame, text="Paths:").grid(row=1, column=0, padx=6, pady=4, sticky="nw")
            self.custom_paths_text = tk.Text(custom_frame, height=2)
            self.custom_paths_text.grid(row=1, column=1, padx=6, pady=4, sticky="ew")

            ttk.Label(custom_frame, text="Ports:").grid(row=2, column=0, padx=6, pady=4, sticky="nw")
            self.custom_ports_text = tk.Text(custom_frame, height=2)
            self.custom_ports_text.grid(row=2, column=1, padx=6, pady=4, sticky="ew")

            ttk.Label(custom_frame, text="Usernames:").grid(row=3, column=0, padx=6, pady=4, sticky="nw")
            self.custom_users_text = tk.Text(custom_frame, height=2)
            self.custom_users_text.grid(row=3, column=1, padx=6, pady=4, sticky="ew")

            progress_frame = ttk.LabelFrame(main, text="Real-time Progress")
            progress_frame.pack(fill="x", pady=(10, 0))
            self.progress = ttk.Progressbar(progress_frame, mode="determinate", maximum=100)
            self.progress.pack(fill="x", padx=6, pady=6)

            stats_line = ttk.Frame(progress_frame)
            stats_line.pack(fill="x", padx=6, pady=(0, 6))
            ttk.Label(stats_line, textvariable=self.files_var).pack(side="left", padx=(0, 16))
            ttk.Label(stats_line, textvariable=self.bytes_var).pack(side="left", padx=(0, 16))
            ttk.Label(stats_line, textvariable=self.lines_var).pack(side="left", padx=(0, 16))
            ttk.Label(stats_line, textvariable=self.hits_var).pack(side="left", padx=(0, 16))
            ttk.Label(stats_line, textvariable=self.skipped_var).pack(side="left", padx=(0, 16))
            ttk.Label(stats_line, textvariable=self.speed_var).pack(side="left", padx=(0, 16))
            ttk.Label(stats_line, textvariable=self.elapsed_var).pack(side="left", padx=(0, 16))

            results_frame = ttk.LabelFrame(main, text="Per-keyword Match Counts")
            results_frame.pack(fill="both", expand=True, pady=(10, 0))
            results_frame.columnconfigure(0, weight=1)
            results_frame.rowconfigure(0, weight=1)

            self.tree = ttk.Treeview(results_frame, columns=("category", "keyword", "matches"), show="headings")
            self.tree.heading("category", text="Category")
            self.tree.heading("keyword", text="Keyword")
            self.tree.heading("matches", text="Matches")
            self.tree.column("category", width=120, anchor="w")
            self.tree.column("keyword", width=420, anchor="w")
            self.tree.column("matches", width=120, anchor="e")
            self.tree.grid(row=0, column=0, sticky="nsew")

            tree_scroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
            tree_scroll.grid(row=0, column=1, sticky="ns")
            self.tree.configure(yscrollcommand=tree_scroll.set)

            status_bar = ttk.Frame(main)
            status_bar.pack(fill="x", pady=(8, 0))
            ttk.Label(status_bar, textvariable=self.status_var).pack(side="left")

        def browse_logs_dir(self) -> None:
            selected = filedialog.askdirectory(title="Select logs directory")
            if selected:
                self.logs_dir_var.set(selected)

        def start_scan(self) -> None:
            if self.running:
                return

            logs_dir = Path(self.logs_dir_var.get().strip())
            if not logs_dir.is_dir():
                messagebox.showerror("Invalid directory", "Please select a valid logs directory.")
                return

            plan = eng.build_match_plan(
                custom_subdomains=self.custom_subdomains_text.get("1.0", "end-1c"),
                custom_paths=self.custom_paths_text.get("1.0", "end-1c"),
                custom_ports=self.custom_ports_text.get("1.0", "end-1c"),
                custom_usernames=self.custom_users_text.get("1.0", "end-1c"),
            )
            if not plan.specs:
                messagebox.showerror("No keywords", "No keywords were configured.")
                return

            workers = max(1, int(self.worker_var.get()))
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = logs_dir / f"{eng.OUTPUT_PREFIX}{stamp}"

            self.current_plan = plan
            self.current_stats = eng.ScanStats(total_files=0, total_bytes=0, specs=plan.specs)
            self.stop_event.clear()
            self.running = True
            self.status_var.set("Starting scan...")
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.reset_tree(plan)

            self.scan_thread = threading.Thread(
                target=self.scan_worker,
                args=(logs_dir, output_dir, plan, workers),
                daemon=True,
            )
            self.scan_thread.start()

        def stop_scan(self) -> None:
            if not self.running:
                return
            self.stop_event.set()
            self.status_var.set("Stopping. Waiting for workers to flush buffered results...")
            self.stop_btn.configure(state="disabled")

        def reset_tree(self, plan: eng.MatchPlan) -> None:
            self.tree.delete(*self.tree.get_children())
            self.tree_items.clear()
            for spec in plan.specs:
                item_id = self.tree.insert("", "end", values=(spec.category, spec.label, "0"))
                self.tree_items[spec.key_id] = item_id

        def scan_worker(self, logs_dir: Path, output_dir: Path, plan: eng.MatchPlan, workers: int) -> None:
            try:
                if self.current_stats is None:
                    raise RuntimeError("Internal error: stats not initialized")

                self.events.put(("status", "Scanning..."))
                snapshot = eng.run_scan(
                    logs_dir=logs_dir,
                    output_dir=output_dir,
                    plan=plan,
                    workers=workers,
                    stop_event=self.stop_event,
                    stats=self.current_stats,
                )
                cancelled = self.stop_event.is_set()

                if snapshot.get("total_files", 0) > 0 and output_dir.exists():
                    eng.write_summary_file(output_dir, snapshot, plan, cancelled)
                    out_dir_value: Optional[str] = str(output_dir)
                else:
                    out_dir_value = None

                self.events.put(("finished", {"cancelled": cancelled, "output_dir": out_dir_value}))
            except Exception as exc:
                if self.current_stats is not None:
                    self.current_stats.finish()
                self.events.put(("fatal_error", str(exc)))

        def refresh_ui(self) -> None:
            if self.current_stats is not None:
                snapshot = self.current_stats.snapshot()
                self.update_progress(snapshot)
                self.update_tree_counts(snapshot.get("keyword_counts", {}))

            while True:
                try:
                    event, payload = self.events.get_nowait()
                except queue.Empty:
                    break
                if event == "status":
                    self.status_var.set(str(payload))
                elif event == "finished":
                    self.handle_finished(payload)
                elif event == "fatal_error":
                    self.handle_fatal_error(str(payload))

            self.after(200, self.refresh_ui)

        def update_progress(self, snapshot: dict) -> None:
            total_files = snapshot.get("total_files", 0)
            processed_files = snapshot.get("processed_files", 0)
            total_bytes = snapshot.get("total_bytes", 0)
            scanned_bytes = snapshot.get("scanned_bytes", 0)
            scanned_lines = snapshot.get("scanned_lines", 0)
            total_hits = snapshot.get("total_hits", 0)
            skipped_not_saved = snapshot.get("skipped_not_saved", 0)
            skipped_local_ip = snapshot.get("skipped_local_ip", 0)
            parsed_ulp = snapshot.get("parsed_ulp_records", 0)
            ignored_non_ulp = snapshot.get("ignored_non_ulp_lines", 0)
            oversized = snapshot.get("skipped_oversized_lines", 0)
            elapsed = snapshot.get("elapsed_seconds", 0.000001)

            self.files_var.set(f"Files: {processed_files:,}/{total_files:,}")
            self.bytes_var.set(f"Bytes: {eng.format_bytes(scanned_bytes)} / {eng.format_bytes(total_bytes)}")
            self.lines_var.set(f"Lines: {scanned_lines:,}")
            self.hits_var.set(f"Hits: {total_hits:,}")
            self.skipped_var.set(
                f"Parsed ULP: {parsed_ulp:,} | Ignored: {ignored_non_ulp:,} | Oversized: {oversized:,} | "
                f"Skipped: {(skipped_not_saved + skipped_local_ip):,} "
                f"(NOT_SAVED={skipped_not_saved:,}, local_ip={skipped_local_ip:,})"
            )
            self.speed_var.set(f"Speed: {eng.format_rate(scanned_bytes / elapsed)}")
            self.elapsed_var.set(f"Elapsed: {elapsed:.1f}s")

            if total_bytes > 0:
                percent = max(0.0, min(100.0, (scanned_bytes / total_bytes) * 100.0))
                self.progress["value"] = percent
            else:
                self.progress["value"] = 0

        def update_tree_counts(self, keyword_counts: dict[str, int]) -> None:
            for key_id, item_id in self.tree_items.items():
                count = keyword_counts.get(key_id, 0)
                self.tree.set(item_id, "matches", f"{count:,}")

        def handle_finished(self, payload: object) -> None:
            if not isinstance(payload, dict):
                return
            self.running = False
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            cancelled = bool(payload.get("cancelled"))
            output_dir = payload.get("output_dir")
            snapshot = self.current_stats.snapshot() if self.current_stats is not None else {}
            errors = snapshot.get("errors", [])
            skipped_not_saved = snapshot.get("skipped_not_saved", 0)
            skipped_local_ip = snapshot.get("skipped_local_ip", 0)
            oversized = snapshot.get("skipped_oversized_lines", 0)
            parsed_ulp = snapshot.get("parsed_ulp_records", 0)
            ignored_non_ulp = snapshot.get("ignored_non_ulp_lines", 0)

            if output_dir:
                self.status_var.set(f"Finished. Output: {output_dir}")
            else:
                self.status_var.set("Finished. No files found to scan.")

            title = "Scan Stopped" if cancelled else "Scan Finished"
            lines = [
                f"Files processed: {snapshot.get('processed_files', 0):,}/{snapshot.get('total_files', 0):,}",
                f"Lines scanned: {snapshot.get('scanned_lines', 0):,}",
                f"Parsed ULP records: {parsed_ulp:,}",
                f"Ignored non-ULP lines: {ignored_non_ulp:,}",
                f"Oversized lines skipped: {oversized:,}",
                f"Skipped NOT_SAVED: {skipped_not_saved:,}",
                f"Skipped local/private IP: {skipped_local_ip:,}",
                f"Matched lines: {snapshot.get('matched_lines', 0):,}",
                f"Total hits: {snapshot.get('total_hits', 0):,}",
            ]
            if output_dir:
                lines.append(f"Output directory: {output_dir}")
            if errors:
                lines.append(f"Errors: {len(errors)} (check summary.txt)")
            messagebox.showinfo(title, "\n".join(lines))

        def handle_fatal_error(self, message: str) -> None:
            self.running = False
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.status_var.set("Fatal error while scanning.")
            messagebox.showerror("Fatal error", message)


def main() -> None:
    if not TK_AVAILABLE:  # pragma: no cover
        hint = (
            "Tkinter is not installed for your Python.\n\n"
            "On Ubuntu/Debian, install it with:\n"
            "  sudo apt-get update && sudo apt-get install -y python3-tk\n\n"
            f"Original import error: {TK_IMPORT_ERROR}"
        )
        raise SystemExit(hint)

    app = ULPSorterApp()
    app.mainloop()


if __name__ == "__main__":
    main()

