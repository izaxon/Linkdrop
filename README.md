# Linkdrop

Rust reference implementation of the Linkdrop protocol in `linkdrop-v1-spec.md`, with a minimalist server and a stronger client-side message chain.

## Workspace layout

- `crates/linkdrop-protocol` - shared protocol models, validation, key handling, encoding, and crypto helpers
- `crates/linkdrop-server` - write-once SQLite-backed drop server with `PUT`, `GET`, and `HEAD /drop/{drop_id}`
- `crates/linkdrop-cli` - `linkdrop` CLI for identity, contact bundles, preferred server rotation, sending, polling, inbox, and history

## Current protocol shape

- message payloads are encrypted with X25519 + HKDF-SHA256 + ChaCha20-Poly1305
- the next `reply_drop` is carried **inside the encrypted payload**, not as top-level envelope metadata
- envelopes may carry an **optional Ed25519 signature**
- the CLI can maintain a **preferred server list** and rotate fresh reply drops across those servers

## Build and test

```bash
cargo test
```

## Run the server

```bash
cargo run -p linkdrop-server -- --bind 127.0.0.1:8080 --database linkdrop-server.db
```

## Run the CLI

```bash
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

## Notes

- The implementation is still HTTP-first for local development and tests. Server URLs still validate against the spec’s HTTPS requirement, with an explicit localhost-only HTTP allowance for development.
- If preferred servers are configured, `contact export` can use them without repeating `--server`.
- Signed envelopes are the default for CLI sends; `--unsigned` is available for interoperability testing.
