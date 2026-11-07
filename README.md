# Linkdrop

> A small encrypted messaging protocol with no required provider, account, SDK, or central service.

Linkdrop is a Rust reference implementation of 1:1 store-and-forward messaging through random, single-use HTTPS drops. The protocol is the product; the Rust workspace proves the frozen V1 wire format can be implemented end to end.

- [Frozen V1 specification](linkdrop-v1-spec.md)
- [Draft V2 specification](linkdrop-v2-spec.md) — asynchronous mailbox, not frozen
- [Protocol changelog](PROTOCOL-CHANGELOG.md)
- [Compatibility policy](COMPATIBILITY.md)
- [Normative V1 vectors](test-vectors/v1) and [draft V2 vectors](test-vectors/v2)
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

## What draft V2 adds

V1 is lock-step: one message consumes one drop and yields one reply drop, so a sender cannot write twice in a row, an expired drop silently kills the chain, and nothing wakes a receiver. The [draft V2 specification](linkdrop-v2-spec.md) keeps the drop model and adds:

- **derived drop chains** — the receiver hands the sender a `chain_key`; drop IDs are `HKDF(chain_key, seq)`, so a sender writes an unbounded run and the receiver watches a sliding window;
- **rotation** — every reply rotates the chain and receive key, so a leaked chain key is a bounded write capability and never yields plaintext;
- **acks and recovery** — sequence numbers, cumulative `ack`, explicit `missing`, resends with the same `msg_id`, expiry detection by `HEAD`, and single-use `rescue` capabilities that repair a conversation without a new bundle;
- **metadata-private envelopes** — the server sees `{ v, sender_ephemeral_key, nonce, ciphertext }`; identity and a mandatory signature are inside ciphertext, as proposed in issue #1;
- **one bundle, both directions** — `DropCapability` carries a one-time `recipient_key`;
- **optional wake-up** — a `?wait=` long-poll extension that no client depends on.

```text
Alice                         drop servers                           Bob
  |-- PUT cap: open, seq 0 ------>|   (Bob's bundle capability)        |
  |-- PUT HKDF(ck, 1): seq 1 ---->|                                    |
  |-- PUT HKDF(ck, 2): seq 2 ---->|   Bob watches HKDF(ck, 1..9)       |
  |                               |<-- HEAD/GET window ---------------|
  |                               |<-- PUT HKDF(ck', 0): ack 2, gen 1 -|
  |<-- GET ----------------------|                                    |
```

The CLI exposes it under `linkdrop v2 ...` next to the unchanged V1 commands. V2 is a draft: its vectors may change until it is frozen.

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
| [`linkdrop-protocol`](crates/linkdrop-protocol) | Wire models, validation, encoding, keys, and crypto; no I/O. `v2` module: draft models, chain derivation, sealing, and an I/O-free conversation state machine |
| [`linkdrop-server`](crates/linkdrop-server) | Axum + SQLite `PUT` / `GET` / `HEAD /drop/{drop_id}` server; accepts V1 and V2 envelopes, periodic TTL cleanup, optional `?wait=` long poll |
| [`linkdrop-cli`](crates/linkdrop-cli) | Identity, contacts, preferred servers, send, poll, inbox, and history; `v2` subcommands for the draft mailbox |

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

### Draft V2 demonstration

One bundle is enough, and the sender never waits for a reply:

```bash
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob v2 export > bob-v2.json
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice v2 import bob-v2.json
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice v2 send --to <bob-contact-id> --text "one"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice v2 send --to <bob-contact-id> --text "two"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob v2 poll            # receives both, creates the contact
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob v2 send --to <alice-contact-id> --text "got them"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice v2 poll --wait 20   # long-polls, marks "one" and "two" delivered
```

`v2 poll` also reports gaps to the peer, resends what expired, and recovers through a rescue capability when a chain drop was taken.

## Implementing another client

Start from the frozen spec, then run the JSON vectors in [test-vectors/v1](test-vectors/v1). A compatible implementation must reproduce the exact X25519 shared secret, HKDF output, ciphertext/tag, signature transcript, and signature, and must reject the invalid cases.

Do not infer wire behavior from README examples alone. If code, documentation, and vectors ever disagree, stop and open an issue: frozen wire meaning cannot be changed silently.
