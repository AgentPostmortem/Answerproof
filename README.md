# answerproof

**Verifiable, tamper-evident receipts for RAG and agent answers.**

![CI](https://github.com/AgentPostmortem/answerproof/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

answerproof attaches a cryptographically-signed audit trail to every generated
answer: which sources were retrieved, which the answer actually used, under
whose permissions, with which model and parameters, plus a content hash of each
source and a Merkle root over the retrieval set. Anyone can later **verify** a
receipt independently, with nothing but the receipt and the library.

It is a real library and verifier, not a wrapper around a model.

---

## Why

RAG and agent systems make claims. When something goes wrong (a leaked
document, a hallucinated fact, a compliance question three months later) the
usual answer is "trust the logs". Logs are mutable, centrally held, and prove
nothing to an outside party.

A **receipt** is different: it is a signed, self-contained artifact that a third
party can check without access to your database, your logs, or your servers. It
turns "trust us" into "verify it yourself".

## Threat model — what a receipt does and does not prove

A receipt **proves**:

- **Integrity.** The query, answer, sources, permissions, model and parameters
  have not been altered since signing. Any mutation breaks the Ed25519
  signature.
- **Source authenticity.** Each source's content hash is recorded; given the
  original content, anyone can confirm it is byte-for-byte what was retrieved.
- **Set membership.** The Merkle root lets you prove a specific source was part
  of the retrieval set (via an inclusion proof) without revealing the others.
- **Provenance of signer.** The signature binds the receipt to a specific
  Ed25519 key; pin that key and you know who issued it.
- **Grounding evidence.** A transparent, rule-based record of which answer
  claims are supported by which sources, and which are unsupported.

A receipt **does not prove**:

- **Truth.** A well-grounded claim can still be wrong if the source is wrong.
- **Semantic correctness of grounding.** Citation binding is n-gram overlap; it
  can miss a correct paraphrase or accept a coincidental lexical match. It is an
  auditable signal, not a judge.
- **Key trust.** answerproof verifies signatures; it does not manage a PKI. You
  decide which public keys you trust.
- **That retrieval was complete or unbiased.** It records what was retrieved,
  not what should have been.

## Install

```bash
pip install answerproof            # core library + CLI
pip install "answerproof[api]"     # + FastAPI verifier service
```

## Quickstart

```python
from answerproof import ReceiptBuilder, SigningKey, verify_receipt

signing_key = SigningKey.generate()

builder = ReceiptBuilder(signing_key)
builder.set_query("How tall is the Eiffel Tower?")
builder.set_answer("The Eiffel Tower is 330 metres tall.")
builder.set_principal("analyst-7", permissions=["kb:paris"], tenant="acme")
builder.set_model("gpt-x", provider="openai", params={"temperature": 0.0})
builder.add_source("doc-1", content="The Eiffel Tower is 330 metres tall.", score=0.92)

receipt = builder.finalize()
print(receipt.to_json())

# Independent verification — needs only the receipt (+ optional source contents).
verdict = verify_receipt(
    receipt,
    source_contents={"doc-1": "The Eiffel Tower is 330 metres tall."},
)
assert verdict.valid
```

## Receipt anatomy

```jsonc
{
  "payload": {
    "schema_version": "1.0",
    "receipt_id": "…",
    "created_at": "2026-07-27T12:00:00Z",
    "query": "How tall is the Eiffel Tower?",
    "answer": "The Eiffel Tower is 330 metres tall.",
    "principal": { "id": "analyst-7", "permissions": ["kb:paris"], "tenant": "acme" },
    "model": { "name": "gpt-x", "provider": "openai", "params": { "temperature": 0.0 } },
    "sources": [
      { "id": "doc-1", "content_hash": "sha256:…", "score": 0.92, "metadata": {} }
    ],
    "cited_source_ids": ["doc-1"],
    "merkle_root": "…",                 // Merkle root over source content hashes
    "citations": [ { "source_id": "doc-1", "quote": "…", "method": "3gram-overlap", "score": 1.0 } ],
    "grounding": { "claims": [ … ], "unsupported_claims": [ … ], "grounding_score": 1.0 }
  },
  "signature": {
    "algorithm": "ed25519",
    "public_key": "…",                  // base64 url-safe raw public key
    "signature": "…"                    // detached signature over canonical payload
  }
}
```

The **payload** is signed; the **signature** envelope carries the detached
Ed25519 signature and the signer's public key. Source *contents* are never
stored in the receipt, only their hashes.

## Verify — including tamper detection

```python
import json
from answerproof import verify_receipt
from answerproof.schema import Receipt

# ... start from a valid `receipt` ...
tampered = json.loads(receipt.to_json())
tampered["payload"]["answer"] = "The Eiffel Tower is in Berlin."
bad = Receipt.from_json(json.dumps(tampered))

verdict = verify_receipt(bad)
assert not verdict.valid
print(verdict.failures()[0].name)   # -> "signature"
```

Every check is independent and reported separately:

| check       | proves                                                          |
| ----------- | -------------------------------------------------------------- |
| `signature` | payload is unmodified and signed by the embedded key           |
| `merkle`    | recomputed Merkle root matches the signed root                 |
| `sources`   | supplied source contents hash to the recorded hashes           |
| `grounding` | citations reference real sources; grounding score is honest    |
| `signer_pin`| (optional) signer public key matches an expected key           |

## Merkle inclusion proofs

Prove one source was in the retrieval set without revealing the rest:

```python
from answerproof.merkle import MerkleTree
from answerproof.verifier import verify_inclusion

hashes = [s.content_hash for s in receipt.payload.sources]
proof = MerkleTree.from_hashes(hashes).proof(0)
assert verify_inclusion(receipt, receipt.payload.sources[0].id, proof).passed
```

Leaves and internal nodes use domain-separated hashing (`0x00` / `0x01`
prefixes) and odd nodes are promoted rather than duplicated, closing common
Merkle forgery vectors.

## CLI

```bash
answerproof keygen                        # print a keypair as JSON
answerproof keygen --out id.key           # write id.key and id.key.pub
answerproof verify receipt.json           # verify (exit 0 = valid, 1 = invalid)
answerproof verify receipt.json --sources sources.json --json
answerproof verify receipt.json --expect-key <base64>   # pin the signer
answerproof inspect receipt.json          # human-readable summary
```

`--sources` takes a JSON object of `{"source_id": "original content", ...}`.

## FastAPI verifier service

```bash
pip install "answerproof[api]"
uvicorn answerproof.api:app --reload
```

- `GET  /health` — liveness.
- `POST /verify` — body `{ "receipt": {...}, "source_contents": {...}, "expected_public_key": "..." }`, returns a JSON verdict.
- `POST /verify/page` — same body, returns a shareable HTML verification page.

The core library works fully standalone; the service is optional.

## Integration snippet

Drop answerproof into an existing RAG pipeline at the seam between retrieval and
generation:

```python
def answer_with_receipt(query, retriever, llm, signing_key, principal):
    hits = retriever.search(query, k=5)
    answer = llm.generate(query, context=[h.text for h in hits])

    builder = ReceiptBuilder(signing_key)
    builder.set_query(query).set_answer(answer)
    builder.set_principal(principal.id, permissions=principal.scopes)
    builder.set_model(llm.name, provider=llm.provider, params=llm.params)
    for h in hits:
        builder.add_source(h.id, content=h.text, score=h.score)

    return answer, builder.finalize()
```

## Run it locally

```bash
git clone https://github.com/AgentPostmortem/answerproof
cd answerproof
pip install -e ".[dev]"
pytest -q                       # full test suite
python examples/demo_rag.py     # produce + verify a receipt, then tamper and re-verify
```

## Contributing

Issues and PRs welcome. Please run `ruff check .` and `pytest` before opening a
PR; CI runs both on Python 3.11 and 3.12. New cryptographic or Merkle behavior
must ship with tests, including a negative (tamper) case.

## License

MIT © royalpinto007. See [LICENSE](LICENSE).
