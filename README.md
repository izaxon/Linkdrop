# Linkdrop

[![CI](https://github.com/izaxon/Linkdrop/actions/workflows/ci.yml/badge.svg)](https://github.com/izaxon/Linkdrop/actions/workflows/ci.yml)

Rust reference implementation of the Linkdrop protocol in `linkdrop-v1-spec.md`, with a minimalist server and a stronger client-side message chain.

---

## Philosophy

Most messaging systems are built around identity: you get an account, you get an inbox, and everyone who knows your address can reach you. The server becomes a long-lived record of who you are and who you talk to.

Linkdrop inverts this. There are no accounts, no global inboxes, and no persistent addresses. Instead, a message goes to a **single-use drop** — a random, unguessable slot on a simple HTTP server. Once used, it is gone. The next message goes to a fresh drop, chosen by the *sender* and carried inside the encrypted payload of the previous one.

The result is a conversation that looks, from the outside, like a stream of unrelated anonymous writes. The server never sees who is talking to whom. It stores encrypted blobs and forgets them.

This design reflects a few deliberate choices:

- **Servers should be boring.** A compliant drop server is little more than a write-once key-value store. It holds no user data, performs no routing decisions, and requires no authentication. It is easy to run, easy to replace, and easy to audit.
- **Trust should be local.** The only things you trust are your own keys and the out-of-band contact exchange with your peer. Everything else — servers, networks, infrastructure — is treated as potentially hostile.
- **Simplicity is a security property.** A small protocol with a fixed cryptographic suite (X25519 + HKDF-SHA256 + ChaCha20-Poly1305 + Ed25519) is easier to implement correctly, easier to audit, and easier to reason about than a flexible one.
- **Privacy through ephemerality.** Drop IDs are one-time capabilities. Once a message is delivered, the address that held it has no further meaning. There is no inbox to enumerate, no contact list to leak, no message history on the server.

Linkdrop V1 is deliberately narrow in scope. No groups, no attachments, no push, no federation. The goal is a protocol that is correct and auditable at its core, with room to extend later without breaking the foundation.

---

## Workspace layout

- `crates/linkdrop-protocol` — shared protocol models, validation, key handling, encoding, and crypto helpers
- `crates/linkdrop-server` — write-once SQLite-backed drop server with `PUT`, `GET`, and `HEAD /drop/{drop_id}`
- `crates/linkdrop-cli` — `linkdrop` CLI for identity, contact bundles, preferred server rotation, sending, polling, inbox, and history

---

## Current protocol shape

- Message payloads are encrypted with X25519 + HKDF-SHA256 + ChaCha20-Poly1305
- The next `reply_drop` is carried **inside the encrypted payload**, not as top-level envelope metadata
- Envelopes may carry an **optional Ed25519 signature**
- The CLI can maintain a **preferred server list** and rotate fresh reply drops across those servers

---

## Build and test

```
cargo test
```

---

## Run the server

```
cargo run -p linkdrop-server -- --bind 127.0.0.1:8080 --database linkdrop-server.db
```

---

## Run the CLI

```
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop init --name "Alice"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop whoami
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop server add --url http://127.0.0.1:8080
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop server list
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop contact export
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop send --to <contact-id> --text "hello"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop send --to <contact-id> --text "interop" --unsigned
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop poll
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop inbox
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop history --contact <contact-id>
```

---

## Notes

- The implementation is HTTP-first for local development and tests. Server URLs still validate against the spec's HTTPS requirement, with an explicit localhost-only HTTP allowance for development.
- If preferred servers are configured, `contact export` can use them without repeating `--server`.
- Signed envelopes are the default for CLI sends; `--unsigned` is available for interoperability testing.
