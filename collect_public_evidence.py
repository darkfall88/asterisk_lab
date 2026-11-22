#!/usr/bin/env python3
"""Veřejný export skutečných laboratorních souborů ze zálohy a lokálního Asterisku 2.

Záměrně exportuje z konfigurace jen soubory upravované v projektu.
Nikdy nekopíruje soukromé klíče. V textových konfiguracích a logách
maskuje přihlašovací údaje, metadata kontroluje pomocí SHA-256.

Zamýšlené spuštění na ThinkPadu L380:
    sudo python3 collect_public_evidence.py \
      --asterisk1-archive /home/gh44sh/asterisk-project/asterisk1/asterisk1-complete.tar.gz \
      --include-asterisk2

Nedotýká se konfigurace běžícího Asterisku, žádný originální archiv nepřepisuje.
"""
from __future__ import annotations
import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent
DEST = ROOT / "originals"
OUTPUT_ZIP = ROOT / "originals_public.zip"

# Obsah čteme pouze z příslušných adresářů; skutečný výběr dále určuje
# allowlist v should_include(). Výchozí konfigurace Asterisku neexportujeme.
A1_PREFIXES = (
    "etc/asterisk/", "etc/hosts", "home/kuribam/asterisk-measurements/",
    "home/kuribam/asterisk-pki/", "root/asterisk-lab-ca/", "var/log/asterisk/",
)
A2_PREFIXES = (
    "etc/asterisk/", "etc/hosts", "home/gh44sh/asterisk-measurements/",
    "home/gh44sh/asterisk-pki/", "var/log/asterisk/",
)

# Potvrzené změny v projektu: účty / trunky PJSIP a telefonní dialplan.
# Připojujeme i výslovně pojmenované zálohy těchto upravených souborů.
EDITED_CONFIGS = {"pjsip.conf", "extensions.conf"}
CONFIG_SNAPSHOTS = re.compile(
    r"^(?:pjsip|extensions)\.conf\.(?:before-[\w-]+|tls-srtp-[\w-]+|bak(?:\.\d+)?|orig|old)$",
    re.I,
)
PUBLISHED_MEASUREMENTS = {"plain", "encrypted", "gsm"}

# Bezpečný výchozí režim pro veřejné zveřejnění.
SECRET_NAME_RE = re.compile(
    r"(^|[/\\.])(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts|"
    r"credentials|passwd|password|shadow|secrets?|private|ca\.key)(?:$|[/\\.])", re.I
)
SECRET_EXTS = {".key", ".p12", ".pfx", ".p8", ".jks", ".kdb", ".kdbx"}
COMPRESSED_EXTS = {".zip", ".tar", ".xz", ".bz2", ".7z", ".zst"}
BINARY_EXTS = {".pcap", ".pcapng", ".cap", ".png", ".jpg", ".jpeg", ".webp", ".ogg", ".wav"}
DROP_PERSONAL_MEDIA = {".wav", ".mp3", ".ogg", ".gsm", ".ulaw", ".alaw"}
PRIVATE_MATERIAL = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----", re.I)
AUTH_LINE = re.compile(
    r"(?im)^(\s*(?:password|passwd|secret|md5_cred|oauth_client_secret|api_key|token|"
    r"auth_password|userpass|passphrase|pin|key_password)\s*[:=]\s*)([^\r\n#;]+)"
)
HTTP_AUTH = re.compile(r"(?im)^(\s*(?:Authorization|Proxy-Authorization)\s*:\s*)[^\r\n]+")
INLINE_AUTH = re.compile(r"(?im)(\b(?:password|passwd|secret|token)\s*[:=]\s*)(\S+)")

class Collector:
    def __init__(self, max_mib: int, include_rtp_conf: bool = False):
        self.max_bytes = max_mib * 1024 * 1024
        self.include_rtp_conf = include_rtp_conf
        self.items = []
        self.skipped = []
        self.excluded_default_config_count = 0

    def should_include(self, rel: str) -> bool:
        """Povoluje jen skutečně upravené konfigurace a relevantní důkazy.

        rtp.conf se přidá pouze při --include-rtp-conf: z dostupných
        podkladů není jisté, že byl oproti výchozímu stavu upravován.
        """
        rel = rel.lstrip("/").removeprefix("./")
        p = PurePosixPath(rel)
        parts = p.parts
        if rel == "etc/hosts":
            # Doplňované laboratorní názvy asterisk1.lab a asterisk2.lab.
            return True
        if len(parts) >= 3 and parts[:2] == ("etc", "asterisk"):
            stem = parts[2:]
            if len(stem) == 1:
                return (stem[0] in EDITED_CONFIGS
                        or CONFIG_SNAPSHOTS.fullmatch(stem[0]) is not None
                        or (self.include_rtp_conf and stem[0] == "rtp.conf"))
            if len(stem) == 2 and stem[0] == "backup-plain":
                return (stem[1] in EDITED_CONFIGS
                        or (self.include_rtp_conf and stem[1] == "rtp.conf"))
            if len(stem) == 2 and stem[0] == "keys":
                return p.suffix.lower() in {".crt", ".csr"}
            return False
        if len(parts) >= 5 and parts[0] == "home" and parts[2] == "asterisk-measurements":
            return (parts[3] in PUBLISHED_MEASUREMENTS
                    and p.suffix.lower() in {".pcap", ".pcapng", ".cap", ".txt", ".log", ".csv"})
        if len(parts) >= 4 and parts[0] == "home" and parts[2] == "asterisk-pki":
            return p.suffix.lower() in {".crt", ".csr", ".ext"}
        if rel == "root/asterisk-lab-ca/ca.crt":
            return True
        if rel.startswith("var/log/asterisk/"):
            return True
        return False

    def record_skip(self, server: str, rel: str, why: str):
        self.skipped.append({"source": server, "path": rel, "reason": why})

    def add(self, server: str, original: str, content: bytes):
        rel = original.lstrip("/").removeprefix("./")
        posix = PurePosixPath(rel)
        if not rel or ".." in posix.parts or posix.is_absolute() or "\\" in rel:
            self.record_skip(server, rel, "Nepovolená relativní cesta")
            return
        if not self.should_include(rel):
            self.excluded_default_config_count += 1
            return
        parts_lower = [x.lower() for x in posix.parts]
        name = posix.name.lower()
        ext = posix.suffix.lower()
        if ".ssh" in parts_lower or ".gnupg" in parts_lower or "voicemail" in parts_lower:
            self.record_skip(server, rel, "Soukromé nebo osobní soubory")
            return
        if ext in SECRET_EXTS or SECRET_NAME_RE.search(rel):
            self.record_skip(server, rel, "Soukromý klíč nebo autentizační soubor")
            return
        if ext in DROP_PERSONAL_MEDIA:
            self.record_skip(server, rel, "Audio a potenciálně osobní hlasový obsah")
            return
        if ext in COMPRESSED_EXTS:
            self.record_skip(server, rel, "Vnořený archiv nelze bezpečně zkontrolovat")
            return
        if len(content) > self.max_bytes:
            self.record_skip(server, rel, f"Soubor větší než {self.max_bytes // 1024 // 1024} MiB")
            return
        if PRIVATE_MATERIAL.search(content):
            self.record_skip(server, rel, "Obsahuje blok soukromého klíče")
            return
        source_sha = hashlib.sha256(content).hexdigest()
        # Gz logy zpracujeme až po rozbalení, aby nebyly publikovány maskované údaje uvnitř.
        if ext == ".gz":
            try:
                content = gzip.decompress(content)
            except Exception:
                self.record_skip(server, rel, "Nelze bezpečně rozbalit gzip")
                return
            if len(content) > self.max_bytes:
                self.record_skip(server, rel, "Rozbalený log překračuje limit")
                return
            if PRIVATE_MATERIAL.search(content):
                self.record_skip(server, rel, "Rozbalený obsah má blok soukromého klíče")
                return
            rel = rel + ".public.txt"
            ext = ".txt"
        binary = ext in BINARY_EXTS
        redacted = False
        if not binary:
            # Velmi staré konfigurační soubory můžou mít jiné kódování.
            if b"\x00" in content[:4096]:
                self.record_skip(server, rel, "Neznámý binární formát")
                return
            txt = content.decode("utf-8", errors="replace")
            before = txt
            txt = AUTH_LINE.sub(r"\1[REDACTED_FOR_PUBLICATION]", txt)
            txt = HTTP_AUTH.sub(r"\1[REDACTED_FOR_PUBLICATION]", txt)
            txt = INLINE_AUTH.sub(r"\1[REDACTED_FOR_PUBLICATION]", txt)
            redacted = txt != before
            if redacted:
                content = txt.encode("utf-8")
        output_rel = f"{server}/{rel}"
        dest = DEST / output_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
        dest.chmod(0o644)
        self.items.append({
            "exported_path": output_rel,
            "source_path": rel,
            "sha256": hashlib.sha256(content).hexdigest(),
            "source_sha256": source_sha,
            "size_bytes": len(content),
            "redacted": redacted,
            "notes": "Autentizační údaje maskovány" if redacted else "Bez změny obsahu (kromě případného rozbalení gzip)"
        })

    def add_tar(self, path: Path, server: str, prefixes: tuple[str, ...]):
        if not path.is_file():
            raise FileNotFoundError(path)
        with tarfile.open(path, mode="r:*") as archive:
            for m in archive:
                if not m.isfile():
                    continue
                rel = m.name.lstrip("/").removeprefix("./")
                if not any(rel == p or rel.startswith(p) for p in prefixes):
                    continue
                if not self.should_include(rel):
                    self.excluded_default_config_count += 1
                    continue
                if m.size > self.max_bytes:
                    self.record_skip(server, rel, "Překročen limit velikosti")
                    continue
                stream = archive.extractfile(m)
                if stream is None:
                    continue
                with stream:
                    self.add(server, rel, stream.read(self.max_bytes + 1))

    def add_system(self, server: str, prefixes: tuple[str, ...]):
        for name in prefixes:
            p = Path("/") / name
            if p.is_file():
                if not self.should_include(name):
                    self.excluded_default_config_count += 1
                    continue
                try:
                    self.add(server, name, p.read_bytes())
                except (OSError, PermissionError) as e:
                    self.record_skip(server, name, f"Nelze číst: {type(e).__name__}")
                continue
            if not p.is_dir():
                continue
            for f in p.rglob("*"):
                if f.is_symlink() or not f.is_file():
                    continue
                try:
                    rel = f.relative_to("/").as_posix()
                    if not self.should_include(rel):
                        self.excluded_default_config_count += 1
                        continue
                    if f.stat().st_size > self.max_bytes:
                        self.record_skip(server, rel, "Překročen limit velikosti")
                        continue
                    self.add(server, rel, f.read_bytes())
                except (OSError, PermissionError) as e:
                    self.record_skip(server, str(f), f"Nelze číst: {type(e).__name__}")

    def finish(self):
        manifest = {
            "title": "ASTERISK TRUNK WITH TLS AND SRTP SUPPORT – veřejné zdrojové přílohy",
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "security_note": "Soukromé klíče a autentizační údaje nejsou publikovány. PCAP jsou binárně věrné originálům.",
            "config_selection": "Pouze pjsip.conf, extensions.conf, jejich pracovní zálohy a upravené /etc/hosts; rtp.conf jen s volbou --include-rtp-conf. Výchozí *.conf se neexportují.",
            "excluded_unrelated_file_count": self.excluded_default_config_count,
            "files": sorted(self.items, key=lambda x: x["exported_path"]),
            "skipped": self.skipped,
        }
        DEST.mkdir(exist_ok=True)
        (DEST / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(DEST.rglob("*")):
                if f.is_file() and not f.is_symlink():
                    z.write(f, f.relative_to(ROOT).as_posix())
        print(f"Exportováno {len(self.items)} souborů, přeskočeno {len(self.skipped)}")
        print(f"Archiv: {OUTPUT_ZIP} ({OUTPUT_ZIP.stat().st_size:,} B)")
        if self.skipped:
            print("Přeskočené položky a důvody jsou v originals/manifest.json")


def main():
    parser = argparse.ArgumentParser(description="Publikovatelné přílohy Asterisk – export s ochranou soukromých klíčů")
    parser.add_argument("--asterisk1-archive", type=Path, help="Původní asterisk1-complete.tar.gz ze zálohy")
    parser.add_argument("--asterisk2-archive", type=Path, help="Volitelný archiv Asterisku 2, pokud existuje")
    parser.add_argument("--include-asterisk2", action="store_true", help="Zahrnout běžící systémové soubory Asterisk 2 na místním počítači")
    parser.add_argument("--max-file-mib", type=int, default=200, help="Limit jednotlivého souboru, výchozí 200 MiB")
    parser.add_argument("--include-rtp-conf", action="store_true", help="Přidat i rtp.conf, pokud byl ve vaší laboratoři skutečně ručně upraven")
    args = parser.parse_args()
    if not (args.asterisk1_archive or args.asterisk2_archive or args.include_asterisk2):
        parser.error("Je nutné uvést alespoň jeden zdroj souborů")
    # Stávající publikované přílohy se při novém exportu přegenerují, zdrojové archivy se nemění.
    if DEST.exists():
        shutil.rmtree(DEST)
    if OUTPUT_ZIP.exists():
        OUTPUT_ZIP.unlink()
    coll = Collector(args.max_file_mib, include_rtp_conf=args.include_rtp_conf)
    if args.asterisk1_archive:
        coll.add_tar(args.asterisk1_archive.expanduser().resolve(), "asterisk1", A1_PREFIXES)
    if args.asterisk2_archive:
        coll.add_tar(args.asterisk2_archive.expanduser().resolve(), "asterisk2", A2_PREFIXES)
    if args.include_asterisk2:
        coll.add_system("asterisk2", A2_PREFIXES)
    coll.finish()

if __name__ == "__main__":
    main()
