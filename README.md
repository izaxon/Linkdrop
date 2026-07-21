# Linkdrop

> A small encrypted messaging protocol with no required provider, account, SDK, or central service.

Linkdrop is a Rust reference implementation of 1:1 store-and-forward messaging through random, single-use HTTPS drops. The protocol is the product; the Rust workspace proves the frozen V1 wire format can be implemented end to end.

- [Frozen V1 specification](linkdrop-v1-spec.md)
- [Protocol changelog](PROTOCOL-CHANGELOG.md)
- [Compatibility policy](COMPATIBILITY.md)
- [Normative V1 vectors](test-vectors/v1)
- [Phase A boundary audit](docs/protocol-boundary-audit.md)
- [Vision](MANIFESTO.md)
- [Agent orientation](AGENTS.md)

## What V1 does

A drop server stores one validated encrypted envelope at a random ID and refuses overwrites. It has no user accounts or directory. Clients exchange contact bundles out of band, encrypt text with X25519 + HKDF-SHA256 + ChaCha20-Poly1305, and carry the next reply drop inside ciphertext.

```text
Alice                         drop server                         Bob
  |                                |                               |
  |-- PUT D0: public envelope ---->|                               |
  |   ciphertext decrypts to:      |                               |
  |   { text, reply_drop: D1 }     |                               |
  |                                |<-- GET D0 ---------------------|
  |                                |                               |
  |<-- GET D1 ---------------------|<-- PUT D1: next envelope ------|
```

Each valid message consumes one drop and offers one new reply drop.

V1 has an important bootstrap limitation: the reply drop contains no encryption key. Both peers must exchange contact bundles, or otherwise know each other's long-term X25519 prekeys, before they can exchange messages in both directions. One-time encrypted receive capabilities are versioned follow-up work in [issue #1](https://github.com/izaxon/Linkdrop/issues/1).

## Security boundary

V1 hides payload content and the encrypted reply drop from a drop server. ChaCha20-Poly1305 authenticates the ciphertext. Envelopes may carry an Ed25519 signature; signatures are the CLI default, while unsigned envelopes remain valid V1.

V1 does not hide everything:

- `sender_identity_key` is public and stable, so a server can correlate envelopes using it.
- Messages target a long-term recipient prekey, so later prekey compromise can decrypt recorded past envelopes.
- A signature is verified against the key in the same envelope; the current client does not bind it to the identity expected for a watched contact.
- Servers still observe IP addresses, drop IDs, timing, and approximate sizes.
- Malicious servers can drop, delay, refuse, or log traffic.
- Local JSON secrets and message state are not yet encrypted, atomic, or transactional.

See the specification and audit for the exact claims. The stronger metadata-private V2 roadmap is tracked in issue #1.

## Workspace

| Crate | Purpose |
| --- | --- |
| [`linkdrop-protocol`](crates/linkdrop-protocol) | Wire models, validation, encoding, keys, and crypto; no I/O |
| [`linkdrop-server`](crates/linkdrop-server) | Axum + SQLite `PUT` / `GET` / `HEAD /drop/{drop_id}` server |
| [`linkdrop-cli`](crates/linkdrop-cli) | Identity, contacts, preferred servers, send, poll, inbox, and history |

The workspace uses Rust 2024.

## Build and validate

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --locked
cargo audit
```

Tests use in-process local servers and temporary state directories; they do not use the public internet.

## Local demonstration

Start a development server:

```bash
cargo run -p linkdrop-server -- --bind 127.0.0.1:8080 --database linkdrop-server.db
```

Create two clients and configure the loopback server:

```bash
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice init --name Alice
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob init --name Bob
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice server add --url http://127.0.0.1:8080
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob server add --url http://127.0.0.1:8080
```

Export and import **both** bundles for bidirectional V1 messaging:

```bash
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice contact export > alice-bundle.json
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob contact export > bob-bundle.json
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice contact import bob-bundle.json
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob contact import alice-bundle.json
```

Then send, poll, and inspect:

```bash
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice send --to <bob-contact-id> --text "hello"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob poll
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob inbox
```

Production `DropRef.server` values require HTTPS. HTTP is accepted only for loopback development.

## Implementing another client

Start from the frozen spec, then run the JSON vectors in [test-vectors/v1](test-vectors/v1). A compatible implementation must reproduce the exact X25519 shared secret, HKDF output, ciphertext/tag, signature transcript, and signature, and must reject the invalid cases.

Do not infer wire behavior from README examples alone. If code, documentation, and vectors ever disagree, stop and open an issue: frozen wire meaning cannot be changed silently.
