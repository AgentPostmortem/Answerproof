"""``answerproof`` command-line interface.

Subcommands:

* ``keygen``  - generate an Ed25519 keypair.
* ``verify``  - verify a receipt file, optionally against source contents.
* ``inspect`` - print a human-readable summary of a receipt.

The CLI is a thin shell over the library; everything it does is available
programmatically too.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .crypto import SigningKey
from .schema import Receipt
from .verifier import verify_receipt


def _load_receipt(path: str) -> Receipt:
    text = Path(path).read_text(encoding="utf-8")
    return Receipt.from_json(text)


def cmd_keygen(args: argparse.Namespace) -> int:
    sk = SigningKey.generate()
    vk = sk.verify_key
    if args.out:
        priv_path = Path(args.out)
        pub_path = priv_path.with_suffix(priv_path.suffix + ".pub")
        priv_path.write_text(sk.to_base64() + "\n", encoding="utf-8")
        pub_path.write_text(vk.to_base64() + "\n", encoding="utf-8")
        try:
            priv_path.chmod(0o600)
        except OSError:
            pass
        print(f"private key -> {priv_path}")
        print(f"public key  -> {pub_path}")
    else:
        print(json.dumps({"private_key": sk.to_base64(), "public_key": vk.to_base64()}, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    receipt = _load_receipt(args.receipt)
    contents: dict[str, str] | None = None
    if args.sources:
        raw = json.loads(Path(args.sources).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            print("error: --sources file must be a JSON object of id -> content", file=sys.stderr)
            return 2
        contents = {str(k): str(v) for k, v in raw.items()}

    verdict = verify_receipt(
        receipt, source_contents=contents, expected_public_key=args.expect_key
    )

    if args.json:
        print(json.dumps(verdict.to_dict(), indent=2))
    else:
        status = "VALID" if verdict.valid else "INVALID"
        print(f"receipt: {receipt.payload.receipt_id}")
        print(f"verdict: {status}")
        for c in verdict.checks:
            mark = "ok " if c.passed else "FAIL"
            line = f"  [{mark}] {c.name}"
            if c.detail:
                line += f" - {c.detail}"
            print(line)
        for s in verdict.skipped:
            print(f"  [skip] {s}")
    return 0 if verdict.valid else 1


def cmd_inspect(args: argparse.Namespace) -> int:
    receipt = _load_receipt(args.receipt)
    p = receipt.payload
    print(f"receipt_id : {p.receipt_id}")
    print(f"created_at : {p.created_at}")
    print(f"schema     : {p.schema_version}")
    print(f"query      : {p.query}")
    print(f"answer     : {p.answer}")
    print(f"principal  : {p.principal.id} perms={p.principal.permissions} tenant={p.principal.tenant}")
    print(f"model      : {p.model.name} provider={p.model.provider} params={p.model.params}")
    print(f"merkle_root: {p.merkle_root}")
    print(f"signer     : {receipt.signature.public_key}")
    print(f"sources    : {len(p.sources)} (cited: {p.cited_source_ids})")
    for s in p.sources:
        cited = "*" if s.id in p.cited_source_ids else " "
        print(f"  [{cited}] {s.id}  score={s.score}  {s.content_hash}")
    print(f"grounding  : score={p.grounding.grounding_score}")
    for claim in p.grounding.claims:
        mark = "grounded" if claim.supported else "UNSUPPORTED"
        print(f"  ({mark}) {claim.text}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="answerproof", description=__doc__)
    parser.add_argument("--version", action="version", version=f"answerproof {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    kg = sub.add_parser("keygen", help="generate an Ed25519 keypair")
    kg.add_argument("--out", help="write private key to this path and public key to <path>.pub")
    kg.set_defaults(func=cmd_keygen)

    vf = sub.add_parser("verify", help="verify a receipt")
    vf.add_argument("receipt", help="path to receipt JSON")
    vf.add_argument("--sources", help="path to JSON object of source id -> content")
    vf.add_argument("--expect-key", help="pin the expected signer public key (base64)")
    vf.add_argument("--json", action="store_true", help="emit the verdict as JSON")
    vf.set_defaults(func=cmd_verify)

    ins = sub.add_parser("inspect", help="print a human-readable receipt summary")
    ins.add_argument("receipt", help="path to receipt JSON")
    ins.set_defaults(func=cmd_inspect)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
