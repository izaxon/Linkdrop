# Protocol changelog

This file records changes to the Linkdrop wire protocol and its normative interpretation. Repository and crate release versions are separate from wire versions.

## V1.0 freeze — 2026-07-20

Status: frozen.

This milestone reconciles the pre-freeze draft with the only existing implementation and publishes the first interoperability contract.

### Documentation corrections that do not change Rust-emitted bytes

- `reply_drop` is specified inside `DecryptedPayload`, matching the Rust implementation. The obsolete draft placed it in the public envelope.
- The required suite is exactly X25519, HKDF-SHA256, and ChaCha20-Poly1305; AES-GCM is not an alternate V1 suite.
- HKDF uses no explicit salt, info `linkdrop-v1-message`, and a 32-byte output.
- ChaCha20-Poly1305 uses a 12-byte nonce, empty associated data, and appends the 16-byte tag to ciphertext.
- Optional Ed25519 signatures and their compact known-field JSON transcript are specified. Unsigned envelopes remain valid.
- The loopback-only HTTP development exception, non-empty text, identifier validation, and unknown-field behavior are stated.
- V1's metadata, authentication, forward-secrecy, bootstrap, local-state, and polling limitations are made explicit.
- Normative deterministic valid and invalid test vectors are published.

### Versioning decision

The earlier document said “Draft / implementation-ready” and no independent compatibility contract or normative vectors existed. V1 is therefore frozen once around the already-emitted Rust layout rather than renumbering existing Rust data without gaining the roadmap's intended one-time-key design.

This is a one-time pre-freeze correction, not permission to reinterpret `v: 1` again. Any later incompatible change uses a new integer wire version.

### Wire impact

- Existing Rust V1 envelopes, payloads, and contact bundles remain byte-compatible.
- An implementation built only from the obsolete draft is not compatible because it exposes `reply_drop` at top level and omits the implemented signature extension.
- The next metadata-private receive-capability design is not part of V1 and must be versioned.

## Pre-freeze draft

The original draft was internally inconsistent with the Rust models, crypto, CLI, README, AGENTS.md, and tests. It did not define a stable interoperability target. The complete reconciliation record is in [docs/protocol-boundary-audit.md](docs/protocol-boundary-audit.md).
