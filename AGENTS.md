# AGENTS.md

This file is for AI coding assistants (Cursor, Claude Code, GitHub Copilot, OpenAI Codex, Aider, Continue, …) and any human who wants the same fast-path orientation an agent gets.

## What this repo is

A Rust reference implementation of **Linkdrop**, a minimal end-to-end encrypted chat protocol built on single-use HTTPS "drops". The protocol is the product. The Rust crates are the first proof it's implementable.

- Wire spec: [linkdrop-v1-spec.md](linkdrop-v1-spec.md) — the source of truth. If code disagrees with the spec, the spec wins.
- Vision and constraints: [MANIFESTO.md](MANIFESTO.md) — why the protocol is shaped the way it is.
- Human-friendly entry: [README.md](README.md).

If you are an agent picking this repo up cold: **read the spec first**, then come back here.

## Workspace map

| Path | Purpose |
| --- | --- |
| [crates/linkdrop-protocol](crates/linkdrop-protocol) | Models, validation, encoding, key handling, X25519 + HKDF-SHA256 + ChaCha20-Poly1305 crypto. No I/O, no networking. |
| [crates/linkdrop-server](crates/linkdrop-server) | Axum + SQLite drop server. Implements `PUT` / `GET` / `HEAD /drop/{drop_id}` exactly per spec §10. |
| [crates/linkdrop-cli](crates/linkdrop-cli) | `linkdrop` binary: identity, contacts, preferred servers, send, poll, inbox, history. |

Per-crate entry points:

- Protocol: [crates/linkdrop-protocol/src/lib.rs](crates/linkdrop-protocol/src/lib.rs), with submodules `model`, `crypto`, `encoding`, `state`, `error`.
- Server: [crates/linkdrop-server/src/lib.rs](crates/linkdrop-server/src/lib.rs) (router) and [crates/linkdrop-server/src/main.rs](crates/linkdrop-server/src/main.rs) (CLI).
- CLI: [crates/linkdrop-cli/src/lib.rs](crates/linkdrop-cli/src/lib.rs) (`LinkdropApp` API used by tests) and [crates/linkdrop-cli/src/main.rs](crates/linkdrop-cli/src/main.rs).

## Canonical commands

Run from the workspace root.

```bash
# Build and run all tests
cargo test

# Lint
cargo clippy --all-targets --all-features

# Run the drop server (dev mode, localhost HTTP allowed)
cargo run -p linkdrop-server -- --bind 127.0.0.1:8080 --database linkdrop-server.db

# Use the CLI
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop init --name "Alice"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop server add --url http://127.0.0.1:8080
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop contact export
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop send --to <contact-id> --text "hello"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop poll
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop inbox
```

These are the same commands exercised by integration tests in [crates/linkdrop-cli/tests/cli_flow.rs](crates/linkdrop-cli/tests/cli_flow.rs) and [crates/linkdrop-server/tests/server_api.rs](crates/linkdrop-server/tests/server_api.rs).

## Conventions

- **Edition:** Rust 2021. Workspace defined in the root [Cargo.toml](Cargo.toml).
- **No real network in tests.** Server tests spin up an in-process Axum app via `linkdrop_server::spawn_test_server`. CLI tests use `tempfile::TempDir` for state dirs. Don't introduce tests that hit the public internet.
- **HTTPS only, except localhost.** The protocol mandates `https://` for `DropRef.server`. The implementation has an explicit localhost HTTP allowance for development; do not weaken this further.
- **No new top-level dependencies without need.** "Zero dependencies" is part of the pitch — keep the dependency surface small and justified.
- **Spec text is normative.** Don't change the wire format casually. Bumping `v` is a protocol decision, not a code-cleanup decision.

## Where to extend

| If you want to… | Touch |
| --- | --- |
| Add a CLI subcommand | [crates/linkdrop-cli/src/lib.rs](crates/linkdrop-cli/src/lib.rs) (logic) and [crates/linkdrop-cli/src/main.rs](crates/linkdrop-cli/src/main.rs) (clap wiring) |
| Add a server route or change storage | [crates/linkdrop-server/src/lib.rs](crates/linkdrop-server/src/lib.rs) |
| Change envelope or payload shape | [crates/linkdrop-protocol/src/model.rs](crates/linkdrop-protocol/src/model.rs) — and update the spec |
| Adjust crypto suite | [crates/linkdrop-protocol/src/crypto.rs](crates/linkdrop-protocol/src/crypto.rs) — and update spec §9 + §19 |
| Add encoding helpers | [crates/linkdrop-protocol/src/encoding.rs](crates/linkdrop-protocol/src/encoding.rs) |
| Touch local state files | [crates/linkdrop-protocol/src/state.rs](crates/linkdrop-protocol/src/state.rs) |

After any change, run `cargo test` from the workspace root.

## What NOT to do

- **Don't break wire compatibility silently.** Any change to envelope JSON, payload JSON, or HTTP semantics requires updating [linkdrop-v1-spec.md](linkdrop-v1-spec.md) and likely a version bump.
- **Don't violate the single-use drop invariant.** A drop server must reject a second successful write to the same `drop_id` (spec §5, §10.1).
- **Don't add server-side accounts, auth, or user directories.** The server is intentionally identity-free.
- **Don't allow non-HTTPS server URLs** outside the existing localhost dev exception.
- **Don't add per-message signatures as a requirement.** Signatures are optional in V1 and must remain interoperable when absent.
- **Don't introduce features that need a "the official" server, SDK, or hosted service.**
- **Don't add LLM/SDK calls or telemetry to the protocol or reference implementation.**
- **Don't bypass tests** with `--no-verify`, `#[ignore]`, or commented-out assertions to "make CI green".

## Good first agent tasks

- Implement a Linkdrop client in another language (TypeScript / browser, Python, Go, Swift) directly from the spec.
- Add JSON test vectors (envelope, payload, contact bundle) to a new top-level `test-vectors/` directory so independent implementations can self-check.
- Build a minimal `wasm32` browser client that polls a drop server with CORS.
- Add a `linkdrop bot` example that auto-replies to incoming drops.
- Fuzz the server's `PUT /drop/{drop_id}` JSON parser.
- Property tests for `encode_base64url` / `decode_base64url` round-trips.

## Reporting back

When you finish a task, summarise:

1. Which files changed.
2. Whether the spec changed (yes/no, and which sections).
3. `cargo test` and `cargo clippy` status.
4. Anything you intentionally did *not* do, and why.
