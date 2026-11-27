"""Audit a built Vanta loader.

Checks:
  * the image has no import directory
  * no forbidden plaintext (paths, API names, KDF labels, passphrase fragment)
  * basic PE facts and resource inventory

Exit code 0 only when every check passes.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import pefile
except Exception:  # pragma: no cover
    pefile = None

FORBIDDEN = [
    b"stage.venv",
    b"wininet.dll",
    b"Mozilla/5.0",
    b"vanta:6f3a",
    b"vanta/outer",
    b"vanta/perm",
    b"vanta/mask",
    b"vanta/aead",
    b"no stage",
    b"CreateFileA",
    b"VirtualAlloc",
    b"GetProcAddress",
    b"LoadLibraryA",
    b"FindResourceA",
    b"EtwEventWrite",
    b"EtwEventWriteEx",
    b"EtwEventWriteFull",
    b"AmsiScanBuffer",
    b"AmsiOpenSession",
    b"amsi.dll",
    b"harden: ",
    b"veh: ",
]


def audit(path: Path) -> list[str]:
    problems: list[str] = []
    data = path.read_bytes()
    if pefile is not None:
        pe = pefile.PE(str(path), fast_load=False)
        imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
        if imports:
            names = [entry.dll.decode(errors="replace") for entry in imports]
            problems.append(f"{path.name}: import table present ({', '.join(names)})")
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            types = []
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                key = entry.name.string.decode(errors="replace") if entry.name else str(entry.id)
                types.append(f"{key}({len(entry.directory.entries)})")
            print(f"[i] {path.name}: resources {', '.join(types) or 'none'}")
        sections = [s.Name.rstrip(b"\0").decode(errors="replace") for s in pe.sections]
        print(f"[i] {path.name}: sections {sections}")
        pe.close()
    for needle in FORBIDDEN:
        if needle in data:
            problems.append(f"{path.name}: plaintext hit {needle!r}")
    if data[:2] != b"MZ":
        problems.append(f"{path.name}: not a PE image")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="audit")
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)
    problems: list[str] = []
    for item in args.paths:
        problems.extend(audit(Path(item)))
    if problems:
        for problem in problems:
            print(f"[-] {problem}", file=sys.stderr)
        return 1
    print("[+] audit clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
