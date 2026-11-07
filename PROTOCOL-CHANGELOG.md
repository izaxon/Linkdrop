# Protocol changelog

This file records changes to the Linkdrop wire protocol and its normative interpretation. Repository and crate release versions are separate from wire versions.

## V2.0 draft — 2026-11-07

Status: draft, not frozen. V1 is unchanged.

V2 is a new integer wire version that makes Linkdrop usable as an asynchronous mailbox. It adopts the issue #1 model (one-time `DropCapability` with `recipient_key`, sender identity and signature inside ciphertext, metadata-private envelope) and removes V1's three structural limits: lock-step turn-taking, the TTL deadlock, and the absence of any wake-up channel.

### Wire model

- `DropCapability { server, drop_id, recipient_key }` replaces `DropRef` as the receive capability; a V2 `ContactBundle` carries `identity_key` and `initial: [DropCapability]` and no long-term prekey. One bundle bootstraps both directions.
- The public envelope is `{ v: 2, sender_ephemeral_key, nonce, ciphertext }`. `msg_id`, `created_at`, identity, signature, and all conversation state are inside ciphertext.
- The payload carries `type`, `msg_id`, `created_at`, `seq`, optional `text`, `ack`, `missing`, `resend_of`, `receive` (a `ReceiveProfile { gen, chain_key, receive_key, servers }`), `rescue` (a `DropCapability`), and the mandatory `sender_identity_key` and `signature`.
- Drop IDs of a direction are derived: `HKDF-SHA256(chain_key, info = "linkdrop-v2-drop-id" || u64be(seq))`; the server is `servers[seq mod len]`. The receiver watches a sliding window; the sender writes without waiting.
- The receiver rotates a direction by advertising a new generation in any reply; at most two generations are live. The implied generation 0 after a capability message derives its chain key from the X25519 shared secret salted with the capability's `drop_id`.
- Message keys are `HKDF-SHA256(X25519(ephemeral, receive_key), salt = drop_id bytes, info = "linkdrop-v2-message-key")`, binding each ciphertext to its drop. ChaCha20-Poly1305 with a 12-byte nonce and empty associated data is unchanged from V1.
- The signature is mandatory and covers a domain-separated binary transcript (`"linkdrop-v2-signature" || 0x00 || ...`) over the consumed drop, the ephemeral and receive keys, every payload member, and the identity key. It is independent of JSON member order.
- Receivers bind chain and rescue messages to the expected identity. A capability message on a bundle capability binds a new, unverified identity.
- Acknowledgement is cumulative (`ack`) with an explicit `missing` list; resends keep `msg_id` and set `resend_of`; receivers deduplicate on `msg_id`. Senders detect expiry by `HEAD`, resend at most three times, and fall back to the peer's single-use `rescue` capability when a drop was taken by foreign bytes.
- Servers SHOULD run retention cleanup periodically. An optional `?wait=<seconds>` long-poll extension on `GET`/`HEAD` is defined; clients must not depend on it.

### Wire impact

- No V1 bytes change. V1 producers and consumers are unaffected; the reference server validates each `PUT` by its own `v`.
- V2 shares the HTTP surface (`PUT`/`GET`/`HEAD drop/{drop_id}`, `201`/`409`/`400`/`413`) with V1.
- Draft vectors are in [test-vectors/v2](test-vectors/v2) and may change until V2 is frozen.

### Deferred

Encrypted and atomic client state, TOFU and fingerprint UI, a second implementation, fuzzing, a standard push-subscription shape, and group or attachment message types remain open under issue #1.

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
