#!/usr/bin/env python3
"""BIND to A10 GSLB Converter — Tkinter GUI.

Author: Nimrod Kravicas
Version: 0.2
Date: 2026-09-27
Developed with major assistance from ChatGPT (GPT-6).

combined_bind_to_a10_gslb_converter_v01.py -- require for the file conversion
The script needs the BIND9 original .zone files under the input folder,
and it will create the A10 GSLB CLI files under the output folder.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import combined_bind_to_a10_gslb_converter as converter


class ConverterGui:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("BIND to A10 GSLB Converter")
        self.root.minsize(760, 620)
        self.result_queue: queue.Queue = queue.Queue()

        self.vars = {
            "input_dir": tk.StringVar(value=str(converter.INPUT_DIR)),
            "output_dir": tk.StringVar(value=str(converter.OUTPUT_DIR)),
            "report_dir": tk.StringVar(value=str(converter.REPORT_DIR)),
            "class_list": tk.StringVar(value=converter.CLASS_LIST),
            "partition_name": tk.StringVar(value=converter.PARTITION_NAME),
            "site_name": tk.StringVar(value=converter.SITE_NAME),
            "site_device": tk.StringVar(value=converter.SITE_DEVICE),
            "site_device_ip": tk.StringVar(value=converter.SITE_DEVICE_IP),
            "policy_name": tk.StringVar(value=converter.POLICY_NAME),
            "reverse_policy_name": tk.StringVar(value=converter.REVERSE_POLICY_NAME),
        }
        self.debug_var = tk.BooleanVar(value=converter.DEBUG_PER_ZONE_FILES)
        self._build_ui()
        self.root.after(150, self._check_queue)

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="BIND9 → A10 GSLB", font=("TkDefaultFont", 17, "bold")).pack(anchor="w")
        ttk.Label(outer, text="Forward and IPv4 reverse zones are detected from each zone's $ORIGIN.").pack(anchor="w", pady=(2, 14))

        form = ttk.Frame(outer)
        form.pack(fill="x")
        rows = [
            ("Input folder", "input_dir", True),
            ("Output folder", "output_dir", True),
            ("Reports folder", "report_dir", True),
            ("Class list", "class_list", False),
            ("Partition", "partition_name", False),
            ("Site name", "site_name", False),
            ("Site device", "site_device", False),
            ("Site device IP", "site_device_ip", False),
            ("Forward policy", "policy_name", False),
            ("Reverse policy", "reverse_policy_name", False),
        ]
        for row_index, (label, key, is_dir) in enumerate(rows):
            ttk.Label(form, text=label, width=19).grid(row=row_index, column=0, sticky="w", padx=(0, 8), pady=4)
            entry = ttk.Entry(form, textvariable=self.vars[key])
            entry.grid(row=row_index, column=1, sticky="ew", pady=4)
            if is_dir:
                ttk.Button(form, text="Browse…", command=lambda k=key: self._browse(k)).grid(row=row_index, column=2, padx=(8, 0), pady=4)
        form.columnconfigure(1, weight=1)

        ttk.Checkbutton(outer, text="Write per-zone CLI files (debug)", variable=self.debug_var).pack(anchor="w", pady=(12, 8))
        ttk.Label(outer, text="SERVICE_PORT, SERVICE_PROTO, SERVICE_IP_PREFIX, and OUTPUT_MODE use the converter defaults.", wraplength=720).pack(anchor="w", pady=(0, 12))

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(0, 10))
        self.run_button = ttk.Button(buttons, text="RUN", command=self._run)
        self.run_button.pack(side="left")
        ttk.Button(buttons, text="Open Folder", command=self._open_output_folder).pack(side="left", padx=(8, 0))
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(buttons, textvariable=self.status_var).pack(side="right")

        ttk.Label(outer, text="Run output").pack(anchor="w")
        self.log = tk.Text(outer, height=10, wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True, pady=(4, 0))

    def _browse(self, key: str):
        chosen = filedialog.askdirectory(initialdir=self.vars[key].get() or str(Path.home()))
        if chosen:
            self.vars[key].set(chosen)

    def _append_log(self, message: str):
        self.log.configure(state="normal")
        self.log.insert("end", message.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _run(self):
        values = {key: variable.get().strip() for key, variable in self.vars.items()}
        if any(not value for value in values.values()):
            messagebox.showerror("Missing value", "Please fill in all folder and configuration fields.")
            return
        self.run_button.configure(state="disabled")
        self.status_var.set("Converting…")
        self._append_log("Starting conversion…")
        debug_per_zone_files = self.debug_var.get()

        def worker():
            try:
                result = converter.convert(
                    input_dir=values["input_dir"],
                    output_dir=values["output_dir"],
                    report_dir=values["report_dir"],
                    debug_per_zone_files=debug_per_zone_files,
                    class_list=values["class_list"],
                    partition_name=values["partition_name"],
                    site_name=values["site_name"],
                    site_device=values["site_device"],
                    site_device_ip=values["site_device_ip"],
                    policy_name=values["policy_name"],
                    reverse_policy_name=values["reverse_policy_name"],
                )
                self.result_queue.put(("success", result))
            except Exception as exc:
                self.result_queue.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _check_queue(self):
        try:
            kind, payload = self.result_queue.get_nowait()
        except queue.Empty:
            self.root.after(150, self._check_queue)
            return
        self.run_button.configure(state="normal")
        if kind == "success":
            self.status_var.set("Complete")
            self._append_log(f"Converted: {payload['converted']}   Skipped: {payload['skipped']}   Failed: {payload['failed']}")
            self._append_log(f"Aggregated CLI: {payload['combined_cli']}")
            self._append_log(f"Reports: {payload['report_dir']}")
        else:
            self.status_var.set("Failed")
            self._append_log(f"ERROR: {payload}")
            messagebox.showerror("Conversion failed", payload)
        self.root.after(150, self._check_queue)

    def _open_output_folder(self):
        folder = Path(self.vars["output_dir"].get()).expanduser()
        folder.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", str(folder)])
            elif os.name == "nt":
                os.startfile(str(folder))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(folder)])
        except OSError as exc:
            messagebox.showerror("Could not open folder", str(exc))


def main():
    root = tk.Tk()
    ConverterGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()
