# Contributing to answerproof

Thanks for your interest in improving answerproof.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a PR

- `ruff check .` passes with no errors.
- `pytest -q` passes.
- `python examples/demo_rag.py` still produces and verifies a receipt.

CI runs ruff and pytest on Python 3.11 and 3.12; all must be green.

## Ground rules

- **Security-sensitive code needs tests, including a negative case.** Any change
  to the crypto, canonicalization, Merkle, or verifier code must ship with a
  test that a tampered or forged input is rejected.
- **Do not change the canonical serialization casually.** It is the basis of
  every signature; a change there invalidates existing receipts. If it must
  change, bump `SCHEMA_VERSION` and document the migration.
- **Keep the core dependency-light.** The library depends only on `pydantic`
  and `cryptography`. FastAPI stays behind the optional `api` extra.

## Reporting security issues

Please open a minimal reproduction. Do not include real keys or private data in
issues or test fixtures.
