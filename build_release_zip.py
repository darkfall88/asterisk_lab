#!/usr/bin/env python3
"""Sestaví veřejný ZIP po importu skutečných laboratorních podkladů.

Použití: python3 build_release_zip.py --require-originals
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parent
OUT = ROOT.parent / (ROOT.name + "_FINAL.zip")
PRIV_EXTS = {".key", ".pfx", ".p12", ".p8", ".kdb", ".jks"}
PRIV_SNIPPETS = (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----",
                 b"-----BEGIN EC PRIVATE KEY-----", b"-----BEGIN OPENSSH PRIVATE KEY-----")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--require-originals", action="store_true", help="Vyžadovat importované soubory z obou Asterisk serverů")
    args = p.parse_args()
    origins = ROOT / "originals"
    if args.require_originals:
        missing = [server for server in ("asterisk1", "asterisk2") if not (origins/server).is_dir()]
        if missing:
            raise SystemExit("Zatím chybí import skutečných souborů: " + ", ".join(missing))
    excluded_dirs = {".venv", "venv", ".git", "__pycache__", ".mypy_cache", ".pytest_cache"}
    files = sorted(f for f in ROOT.rglob("*") if f.is_file() and not f.is_symlink()
                   and not any(part in excluded_dirs for part in f.relative_to(ROOT).parts)
                   and f.suffix.lower() != ".pyc")
    forbidden = []
    for f in files:
        if f.suffix.lower() in PRIV_EXTS or f.name.endswith((".tar.gz", ".tgz", ".tar.xz")):
            forbidden.append(f.relative_to(ROOT).as_posix())
            continue
        # Prohlédneme malé textové soubory, nikoli binární PCAP a screenshoty.
        if f.is_relative_to(ROOT / "originals") and f.stat().st_size <= 3_000_000 and f.suffix.lower() not in {".png", ".jpg", ".jpeg", ".pcap", ".pcapng", ".zip"}:
            blob = f.read_bytes()
            if any(s in blob for s in PRIV_SNIPPETS):
                forbidden.append(f.relative_to(ROOT).as_posix())
    if forbidden:
        raise SystemExit("Veřejný ZIP nebyl vytvořen: nalezeny potenciálně soukromé soubory:\n" + "\n".join(forbidden))
    with zipfile.ZipFile(OUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=8) as z:
        for f in files:
            z.write(f, ROOT.name + "/" + f.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(OUT, "r") as z:
        if z.testzip() is not None:
            raise SystemExit("Poškozený ZIP")
    print(f"Vytvořeno: {OUT} | souborů: {len(files)} | velikost: {OUT.stat().st_size:,} B")
    print(f"SHA-256: {hashlib.sha256(OUT.read_bytes()).hexdigest()}")

if __name__ == "__main__":
    main()
