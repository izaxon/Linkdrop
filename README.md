# Linkdrop

Rust reference implementation of the Linkdrop V1 spec in `linkdrop-v1-spec.md`.

## Workspace layout

- `crates/linkdrop-protocol` - shared protocol models, validation, key handling, encoding, and crypto helpers
- `crates/linkdrop-server` - write-once SQLite-backed drop server with `PUT`, `GET`, and `HEAD /drop/{drop_id}`
- `crates/linkdrop-cli` - `linkdrop` CLI for identity, contact bundles, sending, polling, inbox, and history

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
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop contact export --server http://127.0.0.1:8080
```

The first implementation is HTTP-first for local development and tests. Server URLs still validate against the spec’s HTTPS requirement, with an explicit localhost-only HTTP allowance for development.
