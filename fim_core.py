"""File Integrity Monitor - core engine.
Flow: calculate SHA-256 -> save baseline -> re-hash -> compare -> log.
"""
import csv
import hashlib
import hmac
import json
import os
import time
from datetime import datetime
from pathlib import Path

BASELINE_FILE = "baseline.json"
LOG_FILE = "audit_log.csv"


def hash_file(path: Path, chunk: int = 65536) -> str:
    """SHA-256 of a file, read in chunks so large files are fine."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def scan_folder(folder: str) -> dict:
    """Return {relative_path: {sha256, size, mtime}} for every file in folder."""
    root = Path(folder).resolve()
    result = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            try:
                st = p.stat()
                result[p.relative_to(root).as_posix()] = {
                    "sha256": hash_file(p),
                    "size": st.st_size,
                    "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                }
            except (PermissionError, OSError) as e:
                result[p.relative_to(root).as_posix()] = {"error": str(e)}
    return result


# ---------- Baseline protection (HMAC) ----------
def _sign(data: dict, key: str) -> str:
    msg = json.dumps(data, sort_keys=True).encode()
    return hmac.new(key.encode(), msg, hashlib.sha256).hexdigest()


def save_baseline(folder: str, path: str = BASELINE_FILE, key: str = "") -> dict:
    files = scan_folder(folder)
    doc = {
        "folder": str(Path(folder).resolve()),
        "created": datetime.now().isoformat(timespec="seconds"),
        "files": files,
    }
    if key:
        doc["hmac"] = _sign({k: doc[k] for k in ("folder", "created", "files")}, key)
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
    log_event("BASELINE_CREATED", "-", f"{len(files)} files recorded", LOG_FILE)
    return doc


def load_baseline(path: str = BASELINE_FILE, key: str = "") -> dict:
    with open(path) as f:
        doc = json.load(f)
    if key:
        expected = _sign({k: doc[k] for k in ("folder", "created", "files")}, key)
        if not hmac.compare_digest(expected, doc.get("hmac", "")):
            raise ValueError("BASELINE TAMPERED: HMAC check failed!")
    return doc


# ---------- Compare ----------
def compare(baseline_files: dict, current_files: dict) -> dict:
    b, c = set(baseline_files), set(current_files)
    modified = sorted(
        f for f in b & c
        if baseline_files[f].get("sha256") != current_files[f].get("sha256")
    )
    return {
        "modified": modified,
        "added": sorted(c - b),
        "deleted": sorted(b - c),
        "unchanged": sorted((b & c) - set(modified)),
    }


# ---------- Audit log ----------
def log_event(event: str, file: str, detail: str, path: str = LOG_FILE):
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["timestamp", "event", "file", "detail"])
        w.writerow([datetime.now().isoformat(timespec="seconds"), event, file, detail])


def check(folder: str, baseline_path: str = BASELINE_FILE, key: str = ""):
    """Re-hash folder, compare to baseline, log findings. Returns (report, base, now)."""
    base = load_baseline(baseline_path, key)
    now = scan_folder(folder)
    report = compare(base["files"], now)
    for f in report["modified"]:
        log_event("MODIFIED", f, f"{base['files'][f]['sha256'][:12]}.. -> {now[f]['sha256'][:12]}..")
    for f in report["added"]:
        log_event("ADDED", f, now[f].get("sha256", "")[:12] + "..")
    for f in report["deleted"]:
        log_event("DELETED", f, "file missing")
    return report, base["files"], now


# ---------- Folder selection ----------
def pick_folder() -> str:
    """Open a native folder-chooser dialog (works when running locally).
    Runs in a subprocess so it is safe to call from Streamlit. Returns '' if cancelled."""
    import subprocess
    import sys
    code = (
        "import tkinter as tk\n"
        "from tkinter import filedialog\n"
        "r = tk.Tk(); r.withdraw(); r.attributes('-topmost', True)\n"
        "print(filedialog.askdirectory(title='Select folder to monitor'))\n"
    )
    try:
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=300)
        return out.stdout.strip()
    except Exception:
        return ""


def ask_folder_cli() -> str:
    """Ask for a folder in the terminal; Enter opens the dialog instead."""
    while True:
        p = input("Enter folder path to monitor (or press Enter to browse): ").strip().strip('"')
        if not p:
            p = pick_folder()
        if p and os.path.isdir(p):
            return p
        print("  Not a valid folder, try again.")


# ---------- CLI ----------
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="File Integrity Monitor")
    ap.add_argument("command", choices=["init", "check", "watch"])
    ap.add_argument("folder", nargs="?", help="folder to monitor (asked interactively if omitted)")
    ap.add_argument("--key", default="", help="secret key to HMAC-protect the baseline")
    ap.add_argument("--interval", type=int, default=5, help="seconds between scans (watch)")
    a = ap.parse_args()
    if not a.folder:
        a.folder = ask_folder_cli()
    elif not os.path.isdir(a.folder):
        raise SystemExit(f"Folder not found: {a.folder}")

    if a.command == "init":
        d = save_baseline(a.folder, key=a.key)
        print(f"Baseline saved: {len(d['files'])} files")
    else:
        while True:
            r, _, _ = check(a.folder, key=a.key)
            print(f"[{datetime.now():%H:%M:%S}] modified={r['modified']} added={r['added']} deleted={r['deleted']}")
            if a.command == "check":
                break
            time.sleep(a.interval)
