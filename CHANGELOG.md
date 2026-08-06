# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-08-06

### Changed

- Repository moved to the `AgentPostmortem` GitHub organization; project URLs now
  point at the new location. The package name is unchanged.

## [Unreleased]

## [0.1.0] - 2026-07-27

### Added

- Versioned pydantic receipt schema (`schema_version` 1.0) with a signed
  payload and a detached signature envelope.
- Deterministic JSON canonicalization for stable signatures and hashes.
- SHA-256 content hashing with algorithm-prefixed digests.
- Binary Merkle tree with domain-separated hashing, odd-node promotion, and
  standalone inclusion-proof verification.
- Ed25519 keypair generation, detached signing, and verification.
- Rule-based citation binding and grounding analysis (n-gram overlap) with a
  hallucination signal for unsupported claims.
- `ReceiptBuilder` ergonomic API to record a RAG request and emit a signed
  receipt.
- Independent verifier returning a structured verdict (signature, Merkle,
  sources, grounding, optional signer pinning) plus inclusion-proof helpers.
- `answerproof` CLI: `keygen`, `verify`, `inspect`.
- Optional FastAPI verifier service with JSON and HTML verification endpoints.
- End-to-end demo script and a full pytest suite including tamper-detection.
