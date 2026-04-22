# Linkdrop

> **The best chat protocol — simple, powerful, no lock-in, zero dependencies, AI-bot ready.**

Linkdrop is a tiny end-to-end encrypted messaging protocol built on **single-use message drops**. There are no accounts, no phone numbers, no federation, no push services, and no SDKs you have to trust. A drop server is a write-once key/value slot behind three HTTP verbs. A client is a small program that knows how to encrypt JSON and chain replies. That's the whole thing.

- **Simple** — the entire wire protocol fits in [`linkdrop-v1-spec.md`](linkdrop-v1-spec.md). Three endpoints. One JSON envelope.
- **No lock-in** — any compatible drop server works. Switch servers per message. Run your own in an afternoon.
- **AI-bot ready** — no OAuth, no paid API, no SDK. An agent can implement a Linkdrop client from the spec alone.

> 🤖 **Are you an AI coding agent?** Start with [AGENTS.md](AGENTS.md) and [llms.txt](llms.txt).
> 📜 **Want the philosophy?** Read the [MANIFESTO](MANIFESTO.md).
> 🔧 **Want the wire format?** Read the [spec](linkdrop-v1-spec.md).

---

## Why Linkdrop?

- **Servers are dumb pipes.** A drop server stores a blob at a random ID, exactly once. It cannot read your messages, link your conversations, or hold your identity hostage.
- **Identity belongs to the user.** An Ed25519 keypair on your device. No registration, no recovery email, no provider.
- **Every message is its own envelope.** Each message is uploaded to a fresh, unguessable, single-use drop and carries the next reply drop inside it. Conversations are chains of capabilities, not entries in a database.
- **Interchangeable infrastructure.** Pick any drop server per message. Rotate. Mix. The protocol assumes the network is hostile.
- **Small enough to actually implement.** A working server is a few hundred lines. A working client is a few hundred more. There is nothing to "integrate".
- **Bots are first-class.** Anything that can speak HTTPS and do X25519 + ChaCha20-Poly1305 is a peer. No human-shaped onboarding required.

---

## How it works in 30 seconds

```
   Alice                    drop server(s)                    Bob
   -----                    --------------                    ---
                                                              [creates initial drop D0]
                            [D0  empty   ]   <-- contact bundle (D0 + Bob's keys) --
   encrypt msg₁
   pick fresh D1
   PUT D0 { ..., reply_drop: D1, ciphertext } -->
                            [D0  used    ]
                            [D1  empty   ]                    GET D0 -->  decrypt msg₁
                                                              extract D1 as next drop
                                                              encrypt msg₂, pick D2
                            [D1  used    ] <-- PUT D1 { ..., reply_drop: D2, ciphertext }
                            [D2  empty   ]
   GET D1 --> decrypt msg₂
   extract D2 as next drop
   ...                       conversation continues as a chain of single-use drops
```

1. Bob generates one or more **initial drops** and shares a **contact bundle** (his keys + drop refs) out-of-band.
2. Alice encrypts a message, generates a **fresh reply drop**, and `PUT`s the envelope to one of Bob's initial drops.
3. Bob `GET`s the drop, decrypts the message, and reads Alice's reply drop from inside the payload.
4. Bob replies to Alice's reply drop, including a fresh reply drop of his own.
5. Repeat. Each message consumes exactly one drop and produces exactly one new one.

---

## Try it in 60 seconds

```bash
# 1. Build & test
cargo test

# 2. Start a drop server
cargo run -p linkdrop-server -- --bind 127.0.0.1:8080 --database linkdrop-server.db
```

In a second shell:

```bash
# 3. Two identities, two state dirs
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice init --name "Alice"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob   init --name "Bob"

# 4. Both use the local drop server
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice server add --url http://127.0.0.1:8080
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob   server add --url http://127.0.0.1:8080

# 5. Bob exports a contact bundle, Alice imports it
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob   contact export
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice contact import < bob-bundle.json

# 6. Send and poll
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice send --to <bob-contact-id> --text "hello"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob   poll
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob   inbox
```

That's a working end-to-end encrypted conversation. No account. No third party. No SDK.

---

## Repo map

| Crate | Purpose |
| --- | --- |
| [`crates/linkdrop-protocol`](crates/linkdrop-protocol) | Shared models, validation, key handling, encoding, X25519 + HKDF + ChaCha20-Poly1305 crypto |
| [`crates/linkdrop-server`](crates/linkdrop-server) | Write-once SQLite-backed drop server with `PUT` / `GET` / `HEAD /drop/{drop_id}` |
| [`crates/linkdrop-cli`](crates/linkdrop-cli) | `linkdrop` CLI: identity, contact bundles, preferred-server rotation, send, poll, inbox, history |

Reference implementation in Rust. The wire protocol is language-agnostic — see the [spec](linkdrop-v1-spec.md).

---

## Current implementation notes

- Payloads are encrypted with **X25519 + HKDF-SHA256 + ChaCha20-Poly1305**.
- The next `reply_drop` is carried **inside the encrypted payload**, not as top-level envelope metadata.
- Envelopes may carry an **optional Ed25519 signature**. Signed is the CLI default; `--unsigned` exists for interop testing.
- The CLI can maintain a **preferred server list** and rotate fresh reply drops across those servers.
- HTTPS is required by the spec; HTTP is allowed only for `localhost` development.

---

## Get involved

The protocol wins when there are many independent implementations and many public drop servers. You can help by:

- **Implementing a client** in your favourite language — JS, Python, Go, Swift, anything. The spec is short.
- **Running a public drop server** — write-once storage with a TTL is genuinely a weekend project.
- **Building a bot** — Linkdrop is designed so an LLM agent is just another peer.
- **Filing issues / PRs** — clarifications to the spec, missing test vectors, ergonomic fixes.

Read the [MANIFESTO](MANIFESTO.md) for what we're trying to win, and [AGENTS.md](AGENTS.md) if you're (or you're driving) an AI coding assistant.
