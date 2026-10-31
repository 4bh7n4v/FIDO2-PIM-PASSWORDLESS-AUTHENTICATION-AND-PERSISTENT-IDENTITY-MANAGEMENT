"""Deletes the demo database (and the simulated TPMs) so the demo starts from zero.
Stop the server first.    python SCRIPTS/reset_database.py"""
from pathlib import Path

root = Path(__file__).resolve().parent.parent
removed = []
for pattern_dir, pattern in ((root / "SERVER" / "DATA", "*.sqlite3*"), (root / "CLIENT" / "SIMULATED_TPM", "*.json")):
    for file in pattern_dir.glob(pattern):
        file.unlink()
        removed.append(file.name)
print("Removed:", ", ".join(removed) if removed else "nothing (already clean)")
