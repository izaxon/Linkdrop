# AGENTS.md

This file gives coding assistants and contributors the same repository fast path.

## Source of truth

Linkdrop is a Rust reference implementation of a minimal 1:1 encrypted chat protocol built on single-use HTTPS drops.

Read these in order before wire work:

1. [`linkdrop-v1-spec.md`](linkdrop-v1-spec.md) — frozen normative V1.
2. [`test-vectors/v1`](test-vectors/v1) — normative compatibility bytes and failures.
3. [`COMPATIBILITY.md`](COMPATIBILITY.md) — version-bump rules.
4. [`PROTOCOL-CHANGELOG.md`](PROTOCOL-CHANGELOG.md) — protocol history.
5. [`docs/protocol-boundary-audit.md`](docs/protocol-boundary-audit.md) — Phase A reconciliation.
6. [`MANIFESTO.md`](MANIFESTO.md) and [`README.md`](README.md) — vision and human entry.

If code, spec, and vectors disagree, stop. Do not silently choose one or change `v: 1`; report the conflict and assess compatibility.

## Workspace map

| Path | Purpose |
| --- | --- |
| [`crates/linkdrop-protocol`](crates/linkdrop-protocol) | Models, validation, encoding, key handling, X25519 + HKDF-SHA256 + ChaCha20-Poly1305 crypto; no I/O |
| [`crates/linkdrop-server`](crates/linkdrop-server) | Axum + SQLite drop server |
| [`crates/linkdrop-cli`](crates/linkdrop-cli) | `linkdrop` binary and testable `LinkdropApp` |
| [`test-vectors/v1`](test-vectors/v1) | Language-independent normative vectors |

Entry points:

- Protocol: [`crates/linkdrop-protocol/src/lib.rs`](crates/linkdrop-protocol/src/lib.rs), then `model`, `crypto`, `encoding`, `state`, `error`.
- Server: [`crates/linkdrop-server/src/lib.rs`](crates/linkdrop-server/src/lib.rs) and `main.rs`.
- CLI: [`crates/linkdrop-cli/src/lib.rs`](crates/linkdrop-cli/src/lib.rs) and `main.rs`.

## Canonical commands

Run from the workspace root:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --locked
cargo audit
```

Development server and CLI:

```bash
cargo run -p linkdrop-server -- --bind 127.0.0.1:8080 --database linkdrop-server.db
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop init --name Alice
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop server add --url http://127.0.0.1:8080
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop contact export
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop send --to <contact-id> --text hello
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop poll
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop inbox
```

## Conventions

- **Edition:** Rust 2024, defined in the root `Cargo.toml`.
- **Tests:** no public network. Use `spawn_test_server` and `tempfile::TempDir`.
- **Transport:** HTTPS in production; HTTP only for loopback development.
- **Dependencies:** keep the surface small and justified. The project claims no required provider, account, SDK, or central service—not zero Rust crates.
- **Signatures:** optional in V1. Signed is the CLI default; unsigned must remain interoperable.
- **Versioning:** any incompatible envelope, payload, crypto, validation, or HTTP change requires a new wire version and new vectors.

## Where to extend

| Change | Primary location |
| --- | --- |
| CLI subcommand | `crates/linkdrop-cli/src/lib.rs` and `main.rs` |
| Server route/storage | `crates/linkdrop-server/src/lib.rs` |
| Envelope/payload | `crates/linkdrop-protocol/src/model.rs`, spec, changelog, vectors |
| Crypto | `crates/linkdrop-protocol/src/crypto.rs`, spec §5, changelog, vectors |
| Encoding | `crates/linkdrop-protocol/src/encoding.rs` |
| Local state | `crates/linkdrop-protocol/src/state.rs` |

## Do not

- Change frozen `v: 1` meaning or compatibility silently.
- Put `reply_drop` back in the public V1 envelope.
- Violate the one-successful-write drop invariant.
- Add server-side accounts, auth, or user directories.
- Allow non-HTTPS production server URLs.
- Make signatures mandatory in V1.
- Claim V1 hides its stable public sender identity or provides forward secrecy.
- Introduce a mandatory official server, SDK, hosted service, telemetry, or LLM call.
- bypass tests with `--no-verify`, `#[ignore]`, or weakened assertions.

## Phase A boundary

V1 intentionally documents current limitations: both prekeys are needed for bidirectional messaging; sender identity is public; known-contact identity is not bound; local state is plaintext/non-transactional. Issue #1 owns versioned one-time receive capabilities and subsequent hardening. Do not partially implement that roadmap as an unversioned cleanup.

## Reporting

Report:

1. files changed;
2. spec sections and wire impact;
3. compatibility consequences;
4. test-vector coverage;
5. all four validation command results;
6. intentionally deferred issue #1 work.
