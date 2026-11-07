# Linkdrop V2 Specification

Version: 2.0-draft  
Status: Draft (not frozen; wire bytes may still change)  
Scope: Asynchronous 1:1 encrypted mailbox over write-once drops on interchangeable HTTPS servers.

This document is a draft for wire version `v: 2`. It does not change the meaning of the frozen `v: 1` in [linkdrop-v1-spec.md](linkdrop-v1-spec.md). The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are interpreted as in RFC 2119 and RFC 8174.

V2 is a new integer wire version under [COMPATIBILITY.md](COMPATIBILITY.md). Nothing in V2 is implied by V1 fields, and V1 consumers MUST reject V2 objects. The draft vectors in [test-vectors/v2](test-vectors/v2) are the current interoperability target and will be re-frozen with the final draft.

## 1. Why V2

V1 solves delivery without simultaneity but is a strict turn-taking protocol:

1. **Lock-step.** Every message consumes one drop and returns exactly one `reply_drop`. A sender cannot write two messages in a row until the receiver has polled and replied.
2. **TTL deadlock.** Drops expire (seven days by default). If the receiver misses the window, both the message and the reply drop are gone; nobody is told, nothing is resent, and the chain is dead until a new contact bundle is exchanged out of band.
3. **Delivery is not wake-up.** The receiver must poll. Nothing can tell it that something is waiting.

V2 keeps the V1 thesis: a tiny protocol, no accounts, no directories, no required provider, write-once drops that can move between ordinary HTTPS servers message by message. It adds:

- **Derived drop chains per direction** (§4). The receiver hands the sender a secret `chain_key`; drop IDs are derived from it per sequence number, so the sender can write an unbounded run of messages and the receiver watches a sliding window of future drops.
- **Rotation** (§4.4). The receiver rotates the chain key and its receive key with every reply, so a leaked chain key is a bounded write capability.
- **Acknowledgement, loss detection, and recovery** (§6). Sequence numbers, cumulative acks, explicit `missing` lists, resends, and one-time rescue capabilities repair the conversation without a manual bundle exchange.
- **Metadata-private envelopes and in-ciphertext identity** (§3, §5), as proposed in issue #1. The server sees only an ephemeral key, a nonce, and ciphertext.
- **An optional wake-up channel** (§8) specified as a server extension that no client depends on.

## 2. Encoding and validation

Section 2 of the V1 specification applies unchanged (UTF-8 JSON, unknown members ignored and never meaningful, unpadded base64url, `<algorithm>:<base64url>` keys, server URL and loopback rules, base-path resolution) with these V2 additions:

- A `chain_key` is unpadded base64url of exactly 32 random bytes.
- A `seq`, `gen`, and `ack` value is a JSON integer in `[0, 2^53)`.
- A `drop_id` in a `DropCapability` MUST decode to at least 16 random bytes and SHOULD decode to 32. A derived drop ID (§4.2) always decodes to 32 bytes.
- `created_at` is a signed integer of Unix seconds; V2 prescribes no freshness window.

## 3. Wire objects

### 3.1 DropCapability

A one-time receive capability: where to write, what ID to write under, and which one-time X25519 key to encrypt to.

```json
{
  "server": "https://drop.example",
  "drop_id": "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8",
  "recipient_key": "x25519:NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ"
}
```

All three members are required. The owner keeps the matching X25519 secret with the watched drop and deletes it when the capability is superseded (§4.4).

A capability is single-use: at most one message is ever written to it, and that message is a **capability message** (§4.1).

### 3.2 ContactBundle

```json
{
  "v": 2,
  "display_name": "Bob",
  "identity_key": "ed25519:F0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9U",
  "initial": [
    {
      "server": "https://drop.example",
      "drop_id": "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8",
      "recipient_key": "x25519:NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ"
    }
  ]
}
```

- `v`: required integer equal to `2`.
- `display_name`: optional string with no authentication semantics.
- `identity_key`: required tagged Ed25519 public key.
- `initial`: required non-empty array of `DropCapability` values, each with a distinct `drop_id` and a distinct `recipient_key`.

There is no long-term X25519 prekey. One imported bundle is sufficient for a bidirectional conversation (§4.1). The bundle is exchanged out of band; V2 defines no transport, fingerprint UI, or trust decision for that exchange.

### 3.3 ReceiveProfile

How the owner wants to receive the *next* generation of messages in one direction. It travels only inside ciphertext.

```json
{
  "gen": 1,
  "chain_key": "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8",
  "receive_key": "x25519:BASE64URL",
  "servers": ["https://a.example", "https://b.example"]
}
```

- `gen`: required generation number, strictly greater than every generation previously established in the same direction (§4.4).
- `chain_key`: required 32 random bytes chosen by the owner.
- `receive_key`: required fresh X25519 public key chosen by the owner.
- `servers`: required non-empty array of distinct valid server URLs chosen by the owner.

### 3.4 Payload (AEAD plaintext)

```json
{
  "type": "text",
  "msg_id": "cHFyc3R1dnd4eXp7fH1-fw",
  "created_at": 1777000100,
  "seq": 4,
  "text": "Hello",
  "ack": 2,
  "missing": [1],
  "resend_of": 3,
  "receive": { "gen": 1, "chain_key": "...", "receive_key": "x25519:...", "servers": ["https://a.example"] },
  "rescue": { "server": "https://a.example", "drop_id": "...", "recipient_key": "x25519:..." },
  "sender_identity_key": "ed25519:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
  "signature": "BASE64URL"
}
```

- `type`: required, `"text"` or `"control"`. A control message carries protocol state only.
- `msg_id`: required non-empty base64url; reference clients generate 16 random bytes. A resend reuses the original `msg_id`.
- `created_at`: required Unix seconds.
- `seq`: required sequence number of this message in the sender's direction. It starts at `0` for the first message a sender ever writes to a peer and increases by exactly one per written message, across generations and rescues, for the lifetime of the contact.
- `text`: required non-empty string when `type` is `"text"`; MUST be absent otherwise.
- `ack`: optional highest `seq` the sender has processed from the peer. Absent when nothing has been processed.
- `missing`: optional strictly increasing array of peer sequence numbers below `ack` that the sender has not processed. MUST be absent unless `ack` is present. MUST NOT be empty when present.
- `resend_of`: optional `seq` of an earlier message by the same sender that this message repeats.
- `receive`: optional `ReceiveProfile` for messages flowing toward the sender. Required in a capability message (§4.1).
- `rescue`: optional `DropCapability` the peer may use for recovery (§6.4).
- `sender_identity_key`: required tagged Ed25519 public key.
- `signature`: required base64url of the 64-byte Ed25519 signature over the §5.4 transcript.

Unknown members are ignored and are not part of the transcript. Stable identity and all conversation state live only here, inside ciphertext.

### 3.5 Envelope (public)

```json
{
  "v": 2,
  "sender_ephemeral_key": "x25519:eaYx7t4b-cmPEgMs3q3Q56B5OY_HhriMyEbsia-FpRo",
  "nonce": "AAECAwQFBgcICQoL",
  "ciphertext": "BASE64URL"
}
```

- `v`: required integer equal to `2`.
- `sender_ephemeral_key`: required tagged X25519 public key, fresh per message.
- `nonce`: required base64url of exactly 12 bytes.
- `ciphertext`: required non-empty base64url; bytes include the 16-byte Poly1305 tag.

No message ID, timestamp, identity key, signature, sequence number, or reply capability appears outside ciphertext. Every envelope looks like every other envelope to a server, up to length.

## 4. Chains

A **direction** is one peer writing to the other. Each direction has an independent chain. Both directions together form the conversation.

### 4.1 Capability messages and bootstrap

Alice imports Bob's bundle and takes one `initial` capability `C`. She generates an ephemeral X25519 keypair and computes

```text
ss        = X25519(ephemeral_secret, C.recipient_key)
chain_key = HKDF-SHA256(IKM = ss, salt = decode(C.drop_id), info = "linkdrop-v2-chain-key", L = 32)
```

and writes a message to `C.drop_id` on `C.server`, encrypted per §5. This is a capability message. It MUST carry `receive` (Alice's profile for the Bob→Alice direction, so Bob can reply) and SHOULD carry `rescue`.

The capability message establishes the Alice→Bob chain **generation 0** implicitly:

```text
gen         = 0 (or highest previously established Alice→Bob generation + 1, for a rescue)
chain_key   = as derived above
receive_key = C.recipient_key (Bob keeps its secret as the generation's receive secret)
servers     = [C.server]
```

Bob learns everything he needs from the envelope and the decrypted payload: the ephemeral key gives `ss` and the chain key; `receive` gives him the Bob→Alice generation 0 profile. After one bundle both directions exist.

The capability message has whatever `seq` is next for Alice (0 for a first contact). Chain drops begin at `seq + 1`.

### 4.2 Derived drops

For a direction with active profile `P` and a message with sequence number `n`:

```text
drop_id(P, n) = base64url(HKDF-SHA256(IKM = decode(P.chain_key), salt = absent, info = "linkdrop-v2-drop-id" || u64be(n), L = 32))
server(P, n)  = P.servers[n mod len(P.servers)]
```

`u64be(n)` is the eight-byte big-endian encoding of `n`. The sender writes message `n` to exactly that drop on exactly that server. Drop IDs for different `n` are computationally unrelated; a server cannot tell two drops of the same chain apart from two drops of unrelated chains.

The sender MUST write sequence numbers in order and MUST NOT skip a number. If a `PUT` fails transiently, the sender retries the same drop. If the server answers `409 Conflict`, the sender MUST `GET` the drop and compare bytes: equal bytes mean an earlier ambiguous attempt succeeded; different bytes mean the chain key is compromised and the sender MUST stop using the profile and recover per §6.4.

### 4.3 Watching a window

The receiver of a direction knows `next_seq`, the lowest sequence number it has not processed. It watches drops `drop_id(P, n)` for `n` in `[next_seq, next_seq + W)` for every active profile `P` of that direction (§4.4). `W` is a local choice (reference default 8); senders do not know or depend on it.

The receiver processes drops in increasing `n`. When it processes `n`, it sets `next_seq = n + 1` and the window slides. A receiver SHOULD keep polling in the same pass until a full window is empty, so a long run of consecutive messages is drained in one session.

A drop that returns `404` on every live generation while a higher `n` is present on any of them was lost (expired or discarded). The receiver records `n` as missing (§6.2) and continues; decryption of later messages never depends on an earlier one. A drop that holds bytes which do not open as a valid message for that position (squatted, foreign, or corrupt) is treated the same way. A transport or server error is not a `404`: the receiver stops at that `n` until it can tell.

### 4.4 Rotation (ratchet)

The owner of a direction (its receiver) rotates it by sending a new `ReceiveProfile` with `gen + 1` inside any message it writes in the opposite direction. A sender adopts a profile the first time it writes after processing the message that carried it; it MUST adopt the highest `gen` it has processed and MUST NOT return to an older one.

Because the sender may already have written messages to the old generation before it saw the new profile, the receiver watches both the previous and the new generation until a message arrives on the new one. Once a message with sequence number `t` has been read on generation `g`, every message with sequence number greater than `t` is on generation `g` or later. Since the receiver processes in sequence order, every `n < t` has by then been processed or recorded missing, so it deletes generation `g - 1`, including its receive secret and chain key, as soon as it processes `t`.

A receiver MUST NOT advertise a further generation while an advertised one is still unadopted; it repeats the unadopted profile instead. At most two generations per direction are therefore ever live, and the receiver's trial work is bounded.

Consequences:

- A leaked `chain_key` is a write capability until the owner's next message is adopted. It never yields plaintext (§5.2).
- A leaked receive secret decrypts only messages of its generation, and only together with the matching drop IDs.
- A direction whose owner never writes never rotates. Owners SHOULD send a `control` message carrying a new profile after a local threshold (reference: 64 received messages or 7 days). There is no rotation without a reply, which is a deliberate trade for keeping the sender stateless about the receiver's window.

### 4.5 Rescue capabilities

A `rescue` is a `DropCapability` that the owner watches outside any chain until it is used. The owner SHOULD advertise one unused rescue in every message and MUST replace it after it has been used. A sender keeps the most recent unused rescue it has seen. Its use is defined in §6.4.

## 5. Cryptography

V2 has exactly one suite:

| Purpose | Primitive |
| --- | --- |
| Long-term identity and signatures | Ed25519 |
| Receive keys and sender ephemeral keys | X25519 |
| Key derivation | HKDF-SHA256 |
| Payload encryption | ChaCha20-Poly1305 |
| Random values | Cryptographically secure RNG |

### 5.1 Key agreement

For every message the sender generates a fresh X25519 ephemeral keypair and deletes the secret after encryption:

```text
ss = X25519(sender_ephemeral_secret, receive_key)
```

`receive_key` is the capability's `recipient_key` for a capability message and the active profile's `receive_key` for a chain message. Implementations MUST reject an all-zero shared secret.

### 5.2 Message key

```text
mk = HKDF-SHA256(IKM = ss, salt = decode(drop_id), info = "linkdrop-v2-message-key", L = 32)
```

`drop_id` is the ID of the drop the envelope is written to. Salting with it binds the ciphertext to its position: a copied envelope does not decrypt under another drop, and a chain key alone (no receive secret) derives drop IDs but no message key.

### 5.3 AEAD

```text
key             = mk
nonce           = 12 random bytes
plaintext       = exact payload JSON bytes
associated data = empty
ciphertext      = encrypted bytes followed by the 16-byte Poly1305 tag
```

Receivers MUST reject authentication failure and MUST validate the plaintext object, including the signature, before advancing any state.

### 5.4 Signature transcript

The signature is mandatory and is verified with the `sender_identity_key` carried in the same plaintext. It is a domain-separated binary transcript, independent of JSON serialization:

```text
transcript = "linkdrop-v2-signature" || 0x00
          || item(decode(drop_id))                  consumed drop
          || item(decode(sender_ephemeral_key))     32 raw bytes
          || item(decode(receive_key))              32 raw bytes of the key encrypted to
          || item(utf8(type))
          || item(decode(msg_id))
          || int(created_at)
          || int(seq)
          || opt(utf8(text))
          || opt(int(ack))
          || list(int(missing[i]))
          || opt(int(resend_of))
          || opt(profile(receive))
          || opt(capability(rescue))
          || item(decode(sender_identity_key))      32 raw bytes
```

where

```text
item(b)        = u32be(len(b)) || b
int(i)         = item(ASCII shortest decimal of i, with leading "-" when negative)
opt(x)         = 0x00 when absent, 0x01 || x when present
list(xs)       = u32be(count) || xs...
profile(p)     = int(p.gen) || item(decode(p.chain_key)) || item(decode(p.receive_key)) || list(item(utf8(p.servers[i])))
capability(c)  = item(utf8(c.server)) || item(decode(c.drop_id)) || item(decode(c.recipient_key))
```

Sign the transcript with Ed25519 and encode the 64-byte signature as unpadded base64url in `signature`. Unknown members are not in the transcript.

### 5.5 Identity binding

For a chain message the receiver MUST require `sender_identity_key` to equal the identity already bound to the conversation. A valid signature from a different identity is a protocol failure, not a message from that contact.

For a capability message written to a bundle `initial` capability the sender is unknown. The receiver binds the conversation to the presented identity and marks it **unverified** until the user confirms it out of band. For a capability message written to a `rescue`, the identity MUST equal the bound identity.

## 6. Acknowledgement and recovery

### 6.1 Sender state

A sender keeps every written message until it is acknowledged: `seq`, `msg_id`, the drop written, the plaintext needed to resend, and the time written.

### 6.2 Receiver acknowledgement

Every message a receiver writes carries `ack` (highest peer `seq` processed) and, when there are gaps below it, `missing`. "Processed" means decrypted, verified, and durably stored. A receiver that has nothing to say but has gaps SHOULD write a `control` message after a local delay so the sender learns about the loss.

On processing `ack` and `missing`, the sender deletes acknowledged entries, keeps the entries listed in `missing`, and resends them (§6.3).

### 6.3 Loss detection and resend

A sender detects loss in three ways:

1. the peer lists the sequence number in `missing`;
2. a `HEAD` on a drop the sender wrote successfully returns `404` before any `ack` covers it (expired or discarded by the server);
3. a local timeout the sender chooses.

A resend is a new message with the next `seq`, `resend_of` set to the original `seq`, the same `msg_id`, and the same `text`. Receivers deduplicate on `msg_id`: a known `msg_id` advances `seq` and `ack` state but is not inserted again. A `resend_of` value removes that sequence number from the receiver's `missing` set.

Resending consumes drops and does not stop on its own. Senders SHOULD cap resends (reference: give up after 3 expiries and surface the failure). A message the receiver never fetches within the server's retention is therefore eventually reported as undeliverable rather than silently lost, and the chain itself stays usable: later messages are independent.

### 6.4 Rescue

A sender uses the peer's `rescue` capability when it cannot or must not use the chain:

- a `409` with foreign bytes (§4.2), meaning the chain key leaked;
- the active profile's servers are all unreachable for longer than a local threshold;
- local state for the direction was lost or is distrusted.

The sender writes a capability message to the rescue (§4.1). It establishes a fresh generation for the sender's direction with `gen = highest known + 1`, carries a fresh `receive` profile for the opposite direction, and continues the sender's `seq`. Unacknowledged messages are then resent on the new chain. The receiver, on processing it, discards all older generations of that direction and replaces its rescue.

A rescue is single-use. If the rescue message itself expires unread, the sender has no path until the peer writes again (every peer message carries a new rescue) or a bundle is exchanged out of band. Senders SHOULD keep the latest two unused rescues when the peer advertises more than one.

### 6.5 Retention cleanup

Servers SHOULD delete expired drops periodically while running, not only at startup, so retention is predictable to clients. The reference server runs cleanup every five minutes by default.

## 7. Drop server API

Section 7 of the V1 specification applies: `PUT`, `GET`, and `HEAD` at `drop/{drop_id}`; one successful `PUT` per ID; `201`/`409`/`400`/`413`; exact stored bytes; non-destructive `GET`; retention and size caps.

A V2 `PUT` body is a V2 envelope (§3.5). A server validates only envelope shape. A server MAY accept several wire versions; it MUST NOT reinterpret one as another.

## 8. Optional wake-up extension

Polling a window is cheap (one `HEAD` per watched drop), but a client that wants to sleep needs something to wake it. V2 defines wake-up as an **optional server extension**. Core V2 never depends on it; a client that uses it MUST fall back to polling when the extension is absent.

### 8.1 Long poll

A client MAY append `?wait=<seconds>` to a `GET` or `HEAD` on `drop/{drop_id}`. A server that implements the extension holds the request until the drop exists or the lesser of `wait` and its own maximum elapses, then answers as it would for an immediate request (`200`, or `404` on timeout). A server that does not implement it answers immediately; the client observes a fast `404` and polls instead.

Long poll reveals nothing new to a server: it already sees which drop IDs a client asks for. A client SHOULD long-poll only the lowest watched drop of each active profile.

### 8.2 Push relays

A server MAY offer a subscription endpoint (for example WebSocket or Web Push) that fires when a listed drop ID is written. Such an endpoint is a server-local convenience with no wire-level role; a drop ID is still the only credential. This draft does not standardize its shape.

### 8.3 Honest limits

- Any wake-up channel ties the client to one server per subscription. A chain spread over several servers needs several subscriptions.
- Web Push delivers through the browser vendor's push service. The payload SHOULD be empty or a drop ID only; it is a wake-up, not a message.
- On iOS, Web Push works only for web apps installed to the home screen (iOS 16.4+), is silently throttled, and is unavailable in a browser tab. There is no background fetch for web apps. A reliable wake-up on iOS requires a native wrapper and APNs, which is outside Linkdrop.
- A server that offers push can correlate the subscription with the drop IDs it fires for. Clients that value unlinkability SHOULD prefer polling.

## 9. Security properties and limitations

With correct primitives, secure randomness, uncompromised secrets, and an acceptable out-of-band bundle exchange, V2 provides:

- payload confidentiality and integrity from servers (ChaCha20-Poly1305 under a per-message key);
- mandatory sender authentication, bound to the consumed drop, the ephemeral key, and the whole payload (§5.4), and bound to the expected contact for every chain and rescue message (§5.5);
- metadata-private envelopes: no stable identifier is visible to a server, and drops of one chain are unlinkable by ID;
- forward secrecy per generation: a receive secret is deleted when its generation is superseded, after which recorded envelopes of that generation cannot be decrypted;
- bounded damage from a leaked chain key (write capability until the next adopted rotation, never plaintext);
- resistance to blind writes and to moving envelopes between drops;
- delivery without simultaneity, unbounded consecutive sends, loss detection, and recovery without a manual bundle exchange.

V2 does **not** provide:

- rotation without a reply (§4.4): a silent receiver's generation lives until it writes;
- post-compromise healing of a leaked receive secret within its generation;
- traffic-analysis, IP-address, timing, or size privacy; a server still sees who asks for which drop IDs and when;
- availability against a malicious or absent server; retention is the server's choice, and messages nobody fetches in time are reported, not kept;
- anonymity of the first contact: the bundle owner learns the identity key of whoever writes to an `initial` capability;
- binding of a bundle to a person; TOFU and fingerprint UI are client work;
- deniability: signatures are mandatory and transferable;
- crash-safe or transactional local state in the reference client;
- groups, attachments, multi-device, or any wake-up guarantee.

Possession of a `DropCapability` or a `ReceiveProfile` is a write capability; HTTPS protects them in transit, and they are never sent outside ciphertext except in the initial bundle.

## 10. Reference-client behavior

The Rust CLI (`linkdrop v2 ...`) keeps V1 state files untouched and stores V2 conversations in `conversations.json`. It reuses the V1 Ed25519 identity, uses a window of 8, rotates its receive profile and advertises a rescue in every message it writes, sends a control acknowledgement from `poll` when it finds a gap, resends on `missing` and on observed expiry (at most three times), deduplicates on `msg_id`, resolves `409` by byte comparison, and uses the long-poll extension only when asked (`poll --wait`). State is plaintext JSON written non-atomically and the sender's verification state is never promoted automatically; these are hardening gaps, not wire requirements.

## 11. Versioning, vectors, and deferred work

A V2 producer emits `v: 2` in bundles and envelopes; a consumer rejects other versions. [test-vectors/v2](test-vectors/v2) fixes a contact bundle, a capability message with its shared secret, chain key, message key, exact plaintext bytes, transcript, signature, nonce, ciphertext, and public envelope, a derived-drop table, and invalid cases. Vector private keys and nonces are test-only.

Deferred: encrypted and atomic local state, TOFU/fingerprint UI, a second (TypeScript) implementation, fuzzing, group and attachment types, standardized push subscription shape, and any server-side rate limiting guidance beyond V1's.
