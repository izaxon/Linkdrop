# Linkdrop V1 Specification

Version: 1.0  
Status: Frozen reference profile  
Frozen: 2026-07-20  
Scope: Minimal 1:1 encrypted store-and-forward messaging using write-once drops on interchangeable HTTPS servers.

This document is normative for wire version `v: 1`. The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are interpreted as in RFC 2119 and RFC 8174.

The pre-freeze draft placed `reply_drop` in the public envelope. The Rust reference implementation encrypted it in `DecryptedPayload`. V1 is frozen around the implemented layout because no independent V1 contract or normative vectors had been published. This one-time correction is recorded in [PROTOCOL-CHANGELOG.md](PROTOCOL-CHANGELOG.md). Future incompatible changes require a new integer wire version under [COMPATIBILITY.md](COMPATIBILITY.md).

## 1. Summary and invariants

A receiver publishes a contact bundle containing a long-term Ed25519 identity key, a long-term X25519 prekey, and random single-use drop references. A sender encrypts one text payload to that prekey and writes a public envelope to one drop. The encrypted payload contains exactly one fresh reply drop.

A conforming implementation MUST preserve these invariants:

1. A server permits at most one successful `PUT` for a `drop_id`.
2. Every valid payload contains exactly one `reply_drop`.
3. A sender generates a fresh cryptographically random reply `drop_id` per message.
4. Payload bytes are encrypted before upload.
5. A contact bundle contains at least one initial drop.
6. Basic server operation requires no account or sender authentication.
7. An absent optional signature remains interoperable.

V1 has no accounts, discovery, federation protocol, push channel, attachments, groups, or multi-device synchronization.

## 2. Encoding and validation

### 2.1 JSON

Protocol objects are UTF-8 JSON. Member order is insignificant except for the signature transcript in Section 5.4. Producers MUST emit the named fields with the shown JSON types. The Rust V1 parser ignores unknown object members; consumers MUST ignore unknown members and MUST NOT give them protocol meaning.

### 2.2 Base64url and keys

Binary values use RFC 4648 base64url without `=` padding.

Public keys use `<algorithm>:<base64url>`:

- Ed25519: `ed25519:` plus exactly 32 decoded bytes.
- X25519: `x25519:` plus exactly 32 decoded bytes.

### 2.3 Server URLs

A server is an absolute URL with a host. Production values MUST use `https://`. For local development only, implementations MAY accept HTTP for `localhost`, an IPv4 loopback address, or an IPv6 loopback address.

A path prefix is permitted. Clients append a trailing slash to the base path when absent and resolve `drop/{drop_id}` beneath it. Query and fragment components have no V1 role and SHOULD NOT be generated.

### 2.4 Identifiers and timestamps

- A `drop_id` MUST decode to at least 16 random bytes and SHOULD decode to 32 random bytes.
- A `msg_id` MUST be non-empty base64url. Reference clients generate 16 random bytes.
- `created_at` is a signed JSON integer containing Unix seconds. V1 prescribes no freshness window.
- A present `prev_msg_id` MUST be non-empty base64url.

## 3. Wire objects

### 3.1 DropRef

```json
{
  "server": "https://drop.example",
  "drop_id": "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8"
}
```

Both fields are required and follow Section 2.

### 3.2 ContactBundle

```json
{
  "v": 1,
  "display_name": "Bob",
  "identity_key": "ed25519:F0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9U",
  "prekey": "x25519:NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ",
  "initial_drops": [
    {
      "server": "https://drop.example",
      "drop_id": "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8"
    }
  ]
}
```

- `v`: required integer equal to `1`.
- `display_name`: optional string with no authentication semantics.
- `identity_key`: required tagged Ed25519 public key.
- `prekey`: required tagged X25519 public key.
- `initial_drops`: required non-empty array of valid `DropRef` values.

The bundle is exchanged out of band. V1 defines no transport, fingerprint UI, or trust decision for that exchange.

### 3.3 DecryptedPayload

These UTF-8 JSON bytes are the AEAD plaintext:

```json
{
  "text": "Hello",
  "reply_drop": {
    "server": "https://reply.example",
    "drop_id": "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8"
  },
  "prev_msg_id": "kJGSk5SVlpeYmZqbnJ2enw"
}
```

- `text`: required non-empty UTF-8 string.
- `reply_drop`: required valid `DropRef`.
- `prev_msg_id`: optional non-empty base64url string.

The reply drop MUST NOT appear as a top-level V1 envelope member. Payload member order and insignificant whitespace may vary; encryption operates on the exact serialized bytes.

### 3.4 MessageEnvelope

The public object uploaded to a server is:

```json
{
  "v": 1,
  "msg_id": "cHFyc3R1dnd4eXp7fH1-fw",
  "created_at": 1777000100,
  "sender_identity_key": "ed25519:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
  "sender_ephemeral_key": "x25519:eaYx7t4b-cmPEgMs3q3Q56B5OY_HhriMyEbsia-FpRo",
  "ciphertext": "BASE64URL",
  "nonce": "AAECAwQFBgcICQoL",
  "signature": "OPTIONAL_BASE64URL"
}
```

- `v`: required integer equal to `1`.
- `msg_id`: required identifier from Section 2.4.
- `created_at`: required timestamp from Section 2.4.
- `sender_identity_key`: required tagged Ed25519 public key.
- `sender_ephemeral_key`: required tagged X25519 public key.
- `ciphertext`: required non-empty base64url; bytes include the 16-byte Poly1305 tag.
- `nonce`: required base64url decoding to exactly 12 bytes.
- `signature`: optional base64url decoding to exactly 64 bytes.

Unsigned producers omit `signature`; they do not emit `null`. Consumers MUST accept absence. If present, the signature MUST verify under Section 5.4 or the message is invalid.

## 4. Message flow

### 4.1 First message

1. Bob generates long-term Ed25519 and X25519 prekey keypairs.
2. Bob generates initial drops, watches them, and shares a `ContactBundle`.
3. Alice imports it, consumes one initial drop locally, and generates a fresh reply drop.
4. Alice encrypts the payload to Bob's prekey and uploads the envelope.
5. Bob downloads, validates, optionally verifies, and decrypts it.
6. Bob stores the encrypted `reply_drop` as the next outgoing drop.

### 4.2 V1 reply limitation

A reply still encrypts to the other peer's long-term X25519 prekey. The encrypted reply drop contains no encryption key. One bundle can deliver a first message and return drop, but the recipient cannot reply until they also know the sender's prekey. The Rust bidirectional test therefore exchanges both bundles.

This documents frozen V1 behavior. Versioned one-time receive capabilities are deferred to issue #1.

### 4.3 Duplicates

Clients SHOULD remember processed `msg_id` values per contact. A duplicate MUST NOT be inserted again or replace the active next outgoing drop.

## 5. Cryptography

V1 has exactly one interoperable suite:

| Purpose | Primitive |
| --- | --- |
| Long-term identity | Ed25519 |
| Recipient prekey and sender ephemeral key | X25519 |
| Key derivation | HKDF-SHA256 |
| Payload encryption | ChaCha20-Poly1305 |
| Random values | Cryptographically secure RNG |

AES-GCM and alternate KDF inputs are not V1 compatible.

### 5.1 Key agreement

For every message the sender generates a fresh X25519 ephemeral keypair:

```text
shared_secret = X25519(sender_ephemeral_secret, recipient_prekey_public)
```

The receiver uses its long-term prekey secret and the published ephemeral public key. V1 validates the tag and 32-byte length; the reference implementation adds no separate low-order/all-zero rejection rule.

### 5.2 KDF

Derive exactly 32 bytes using HKDF-SHA256:

```text
IKM  = shared_secret
salt = absent (the RFC 5869 all-zero HashLen default)
info = UTF-8 bytes of "linkdrop-v1-message"
L    = 32
```

### 5.3 AEAD

Serialize the payload to UTF-8 JSON, generate a fresh random 12-byte nonce, and use:

```text
key             = Section 5.2 output
nonce           = 12 random bytes
plaintext       = exact payload JSON bytes
associated data = empty
ciphertext      = encrypted bytes followed by the 16-byte Poly1305 tag
```

Receivers MUST reject authentication failure and validate the plaintext object before advancing state.

### 5.4 Optional Ed25519 signature

The signature is self-contained: it is verified with `sender_identity_key` in the same public envelope. It does not prove equality with a previously expected contact key.

Serialize exactly these seven members in this order, with no whitespace and `signature` omitted:

```json
{"v":1,"msg_id":"...","created_at":1777000100,"sender_identity_key":"ed25519:...","sender_ephemeral_key":"x25519:...","ciphertext":"...","nonce":"..."}
```

Use the exact member spelling above, shortest decimal JSON integer forms, normal JSON string escaping, and UTF-8. Sign those bytes with Ed25519 and encode the 64-byte signature as unpadded base64url. Unknown envelope members are not in the transcript, are unauthenticated, and MUST be ignored.

## 6. Security properties and limitations

With correct primitives, secure randomness, uncompromised secrets, and acceptable out-of-band exchange, V1 provides payload confidentiality from servers, payload integrity through AEAD, optional authorship relative to a self-asserted public identity key, and resistance to blind writes through unguessable drop IDs.

V1 does **not** provide:

- forward secrecy after compromise of the recipient's long-term X25519 prekey;
- sender unlinkability from a server, because `sender_identity_key` is public and stable;
- traffic-analysis, IP-address, timing, or size privacy;
- availability against a malicious server;
- binding to the identity expected for a watched contact;
- bidirectional bootstrap from only one contact bundle;
- crash-safe or transactional local state.

Possession of a drop ID is the server-side write capability. HTTPS protects it in transit, but servers can log it. Unsigned messages remain valid V1.

## 7. Drop server API

A server exposes `PUT`, `GET`, and `HEAD` at `drop/{drop_id}` beneath the base URL. The path segment is opaque; clients validate its entropy.

### 7.1 PUT

Request: `Content-Type: application/json`, body `MessageEnvelope`.

- Unused ID and valid envelope: store exact request bytes; `201 Created`.
- Already used: `409 Conflict`.
- Malformed JSON or invalid known fields: `400 Bad Request`.
- Above configured limit: `413 Payload Too Large`.
- Storage failure: `5xx`.

A server MUST never overwrite a successfully stored drop.

### 7.2 GET and HEAD

GET returns `200 OK` with `application/json` and stored bytes when present, otherwise `404 Not Found`. GET is not destructive; reads may repeat until retention cleanup.

HEAD returns `200 OK` when present and `404 Not Found` otherwise.

Servers SHOULD cap size, expire old drops, and rate-limit abuse. Reference defaults are 16 KiB and seven days. CORS, logging, health checks, and deployment topology are not prescribed.

## 8. Reference-client behavior

The Rust CLI signs by default, accepts unsigned envelopes, permits HTTP only for loopback development, and rotates reply servers. It stores secrets and state in plaintext JSON, writes non-atomically, has no durable outbox, stops on some per-server poll errors, and consumes a watched drop after a fetched invalid or duplicate envelope. These are known hardening gaps, not extra wire requirements.

## 9. Versioning and interoperability

A V1 producer emits `v: 1`; a V1 consumer rejects other versions. Contact-bundle and envelope versions are separate fields but both equal `1`. Local state versions are implementation-specific, not wire versions.

Implementations interoperate when they agree on object validation, Section 5 bytes, optional signature behavior, Section 7 HTTP semantics, and [the normative vectors](test-vectors/v1).

Any incompatible change requires a new integer wire version. See [COMPATIBILITY.md](COMPATIBILITY.md).

## 10. Normative vectors and deferred work

[test-vectors/v1/normative.json](test-vectors/v1/normative.json) freezes a contact bundle, X25519/KDF inputs and output, exact payload bytes, nonce/ciphertext/tag, signature transcript/signature, valid public envelope, and invalid examples. Its private keys and nonce are test-only and MUST NOT be reused.

One-time receive keys, metadata-private envelopes, expected-contact binding, TOFU/fingerprints, crash-safe state, durable retries, server hardening, independent implementations, browser clients, bots, attachments, groups, and push are outside V1 and require versioned follow-up work.
