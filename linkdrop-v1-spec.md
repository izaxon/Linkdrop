# Linkdrop V1 Specification

Version: 1.0  
Status: Draft / implementation-ready  
Scope: Minimal 1:1 encrypted store-and-forward messaging using write-once drops on interchangeable HTTPS drop servers.

---

## 1. Overview

Linkdrop is a minimal messaging protocol built around **single-use message drops**.

A sender does **not** send a message to a global account, phone number, or inbox.  
Instead, a sender writes exactly one encrypted message to a **single-use drop address** supplied by the recipient.

Each message includes a fresh **reply drop**, allowing the conversation to continue as a chain.

### Core properties

- 1:1 messaging only in V1
- store-and-forward
- end-to-end encrypted payloads
- interchangeable, untrusted drop servers
- no server-side user accounts required
- no discovery/federation required
- minimal HTTP API

---

## 2. Design goals

### 2.1 Goals

- Extremely simple protocol and deployment model
- Minimal server responsibilities
- No server-side contact graph
- No server-side readable message content
- Ability to use any compatible drop server
- Conversation model based on chained reply drops
- Easy to implement as a small server and CLI/desktop/web client

### 2.2 Non-goals for V1

- Group chat
- Attachments
- Multi-device synchronization
- Push notifications
- Federation
- Peer-to-peer transport
- WebRTC
- Personal node hosting / direct node discovery
- Strong metadata protection against global adversaries
- Perfect forward secrecy ratchets beyond basic session derivation
- Read receipts

---

## 3. Terminology

### Identity key
Long-term public/private signing identity of a user.

### Prekey
Public key used by others to establish encrypted messages to that user.

### Drop server
An HTTPS service that stores a blob at a random single-use drop identifier.

### Drop
A write-once addressable storage slot on a drop server.

### Initial drop
A drop included in a contact bundle to allow starting a conversation.

### Reply drop
A newly generated drop included in each outgoing message. The recipient uses it for the next reply.

### Contact bundle
A portable object shared directly between users containing identity and one or more initial drops.

### Message envelope
The top-level JSON object uploaded to a drop server.

### Payload
The encrypted message content inside the envelope.

---

## 4. High-level protocol model

A conversation starts when:

1. User B creates one or more initial drops.
2. User B packages these drops with identity metadata in a contact bundle.
3. User B shares the contact bundle out-of-band with User A.
4. User A encrypts a message to User B and uploads it to one initial drop.
5. User A includes a fresh reply drop in the envelope.
6. User B retrieves and decrypts the message.
7. User B replies by uploading to A's reply drop, including a new reply drop of B's own.
8. The conversation continues as a chain.

### Key idea

Each message consumes exactly one drop and produces exactly one new reply drop.

---

## 5. Protocol invariants

These are mandatory V1 invariants.

1. A drop server MUST permit at most one successful write to a given `drop_id`.
2. A message envelope MUST include exactly one `reply_drop`.
3. A client MUST generate a fresh `reply_drop` for every outgoing message.
4. A drop server MUST NOT require user accounts for basic operation.
5. Message content MUST be encrypted before upload.
6. Drop identifiers MUST be cryptographically random and unguessable.
7. A contact bundle MUST contain at least one initial drop.

---

## 6. Trust and threat model

### 6.1 What is trusted

- The local client and local secret keys
- Cryptographic algorithms
- Out-of-band exchange of contact bundles

### 6.2 What is not trusted

- Drop servers
- Network intermediaries
- Other public infrastructure

### 6.3 What V1 protects

- Message content confidentiality from servers
- Message payload integrity
- Resistance to trivial unsolicited writes via unguessable drop IDs

### 6.4 What V1 does not fully protect

- Traffic analysis
- Timing metadata
- Global network observers
- Malicious servers dropping messages
- Correlation between users based on external observations

---

## 7. Data model

All protocol objects are JSON encoded as UTF-8.

### 7.1 DropRef

A reference to a single-use drop.

```json
{
  "server": "https://drop.example.org",
  "drop_id": "base64url-random"
}
```

#### Fields

- `server`: HTTPS origin or base URL of the drop server
- `drop_id`: random opaque identifier

#### Rules

- `server` MUST use `https://`
- `drop_id` MUST be base64url without padding
- `drop_id` MUST encode at least 16 random bytes
- `drop_id` SHOULD encode 32 random bytes

---

### 7.2 ContactBundle

Portable bundle shared directly between users.

```json
{
  "v": 1,
  "display_name": "Bob",
  "identity_key": "ed25519:BASE64URL...",
  "prekey": "x25519:BASE64URL...",
  "initial_drops": [
    {
      "server": "https://drop1.example.org",
      "drop_id": "..."
    },
    {
      "server": "https://drop2.example.org",
      "drop_id": "..."
    }
  ]
}
```

#### Fields

- `v`: protocol version, integer
- `display_name`: optional human-readable name
- `identity_key`: public identity key
- `prekey`: public encryption prekey
- `initial_drops`: array of `DropRef`

#### Rules

- `v` MUST be `1`
- `identity_key` MUST use the format `ed25519:<base64url>`
- `prekey` MUST use the format `x25519:<base64url>`
- `initial_drops` MUST contain at least 1 entry
- Clients SHOULD generate 1 to 3 initial drops per contact bundle in V1

---

### 7.3 MessageEnvelope

Top-level object stored on a drop server.

```json
{
  "v": 1,
  "msg_id": "base64url-random",
  "created_at": 1777000100,
  "reply_drop": {
    "server": "https://drop.example.org",
    "drop_id": "..."
  },
  "sender_identity_key": "ed25519:BASE64URL...",
  "sender_ephemeral_key": "x25519:BASE64URL...",
  "ciphertext": "BASE64URL...",
  "nonce": "BASE64URL..."
}
```

#### Fields

- `v`: protocol version
- `msg_id`: unique message identifier
- `created_at`: UNIX timestamp in seconds
- `reply_drop`: `DropRef` for the next reply
- `sender_identity_key`: sender's public identity key
- `sender_ephemeral_key`: sender's ephemeral X25519 public key
- `ciphertext`: AEAD-encrypted payload bytes, base64url encoded
- `nonce`: AEAD nonce, base64url encoded

#### Rules

- `v` MUST be `1`
- `msg_id` MUST be unique per client
- `reply_drop` MUST be present
- `sender_identity_key` MUST match `ed25519:<base64url>`
- `sender_ephemeral_key` MUST match `x25519:<base64url>`
- `ciphertext` MUST be non-empty
- `nonce` MUST be the correct size for the chosen AEAD

---

### 7.4 Decrypted payload

The decrypted JSON stored inside `ciphertext`.

```json
{
  "text": "Hello",
  "prev_msg_id": "optional"
}
```

#### Fields

- `text`: message text, UTF-8
- `prev_msg_id`: optional previous message reference

#### Rules

- `text` MUST be a UTF-8 string
- V1 payload MUST contain only text
- V1 clients MAY omit `prev_msg_id`
- V1 clients SHOULD include `prev_msg_id` when replying if known

---

## 8. Encoding rules

### 8.1 JSON
All JSON MUST be UTF-8.

### 8.2 Base64url
All binary data in JSON MUST be encoded as base64url without padding.

### 8.3 URLs
All server URLs MUST be HTTPS URLs.

### 8.4 Timestamps
Timestamps use UNIX seconds since epoch.

---

## 9. Cryptography

V1 intentionally keeps cryptography simple.

### 9.1 Required primitives

Recommended choices:

- Identity keys: Ed25519
- Encryption prekeys: X25519
- Message encryption: ChaCha20-Poly1305 or AES-256-GCM
- KDF: HKDF-SHA256
- Randomness: cryptographically secure RNG

### 9.2 Key types

Each user has:

- one long-term Ed25519 identity keypair
- one long-term X25519 prekey keypair

Each outgoing message also generates:

- one fresh X25519 ephemeral keypair

### 9.3 Basic key agreement

For V1, derive a shared secret using:

- sender ephemeral private key
- recipient prekey public key

Then derive a symmetric encryption key with HKDF.

#### Suggested derivation inputs

- DH result: `X25519(sender_ephemeral_secret, recipient_prekey_public)`
- HKDF salt: optional fixed or protocol-specific value
- HKDF info: `"linkdrop-v1-message"`

### 9.4 Encryption model

The sender encrypts the JSON payload with the derived symmetric key using AEAD.

The `reply_drop` remains outside the ciphertext in V1 for protocol simplicity, but is still protected by transport and envelope integrity assumptions only.  
A future version may move `reply_drop` inside the ciphertext.

### 9.5 Signature requirements

V1 does **not** require per-message signatures.  
The server is untrusted, but message authenticity is loosely tied to possession of the correct decryption relation.

If desired, implementations MAY add optional detached signatures later, but they are out of scope for V1 interoperability.

---

## 10. Drop server API

A compliant drop server exposes the following endpoints:

- `PUT /drop/{drop_id}`
- `GET /drop/{drop_id}`
- `HEAD /drop/{drop_id}`

The `{drop_id}` path segment is opaque to the server.

### 10.1 PUT /drop/{drop_id}

Store a message envelope at a single-use drop.

#### Request

- Method: `PUT`
- Path: `/drop/{drop_id}`
- Content-Type: `application/json`
- Body: `MessageEnvelope`

#### Server behavior

- If `drop_id` is unused:
  - validate basic JSON structure
  - store the exact request body
  - mark the drop as used
  - return `201 Created`
- If `drop_id` is already used:
  - return `409 Conflict`
- If body is too large:
  - return `413 Payload Too Large`
- If JSON is invalid:
  - return `400 Bad Request`

#### Notes

- The server MUST NOT permit overwriting an existing drop
- The server MUST treat a drop as single-use regardless of sender identity
- The server SHOULD store the exact original bytes or a normalized equivalent preserving all fields

---

### 10.2 GET /drop/{drop_id}

Retrieve the message envelope if present.

#### Request

- Method: `GET`
- Path: `/drop/{drop_id}`

#### Responses

- `200 OK` with JSON body if a message is present
- `404 Not Found` if no message is present

#### Notes

- V1 does not require automatic deletion on read
- V1 clients should be prepared for repeated successful reads until TTL cleanup
- A future version may add read-once semantics, but not V1

---

### 10.3 HEAD /drop/{drop_id}

Check whether a message exists for a drop.

#### Request

- Method: `HEAD`
- Path: `/drop/{drop_id}`

#### Responses

- `200 OK` if present
- `404 Not Found` if absent

---

## 11. Drop server storage rules

A compliant server MUST:

- store at most one envelope per `drop_id`
- never overwrite an existing stored envelope
- support HTTPS
- not require authentication for basic V1 operation

A server SHOULD:

- enforce a maximum request body size
- implement TTL cleanup for old drops
- implement rate limiting
- support CORS if a browser client is expected

### Recommended operational defaults

- Maximum stored envelope size: 16 KiB
- Drop TTL: 7 days
- Rate limiting: implementation-defined

---

## 12. Client behavior

A compliant client MUST:

- generate identity keys
- generate encryption prekeys
- create contact bundles
- import contact bundles
- generate random drop IDs
- create fresh reply drops for each outgoing message
- encrypt and decrypt message payloads
- upload envelopes to drop servers
- poll or fetch pending drops
- maintain local message history

A client SHOULD:

- track message IDs to prevent duplicates
- track consumed drops locally
- include `prev_msg_id` when replying
- allow users to configure preferred drop servers
- generate multiple initial drops in a contact bundle

---

## 13. Client local state

The implementation SHOULD maintain local state containing at least:

### 13.1 Identity

- Ed25519 secret key
- Ed25519 public key
- X25519 prekey secret key
- X25519 prekey public key

### 13.2 Contacts

For each contact:

- display name
- identity public key
- prekey public key
- unused known initial drops or next incoming drops if tracked
- conversation history

### 13.3 Messages

For each message:

- message ID
- sender/recipient contact reference
- drop used for send
- reply drop generated
- local state: pending/sent/failed
- decrypted text
- timestamp

---

## 14. Contact exchange

Contact bundles are exchanged out-of-band.

Examples:

- QR code
- copy/paste
- file
- local share sheet
- direct text transport
- manual import/export

### V1 assumption

The protocol assumes the contact bundle reaches the peer through some trusted or acceptable external channel.  
V1 does not define that exchange channel.

---

## 15. Message flows

### 15.1 Conversation start

1. Bob creates one or more initial drops on chosen drop servers.
2. Bob exports a `ContactBundle`.
3. Alice imports Bob's bundle.
4. Alice generates a fresh reply drop for herself.
5. Alice constructs and encrypts a `MessageEnvelope`.
6. Alice uploads the envelope to one of Bob's initial drops.
7. Bob later polls or fetches the relevant drop and decrypts the message.

---

### 15.2 Reply flow

1. Bob reads Alice's message.
2. Bob extracts Alice's `reply_drop`.
3. Bob generates a new reply drop for himself.
4. Bob encrypts a reply payload.
5. Bob uploads the envelope to Alice's reply drop.
6. Alice later fetches and decrypts it.

---

### 15.3 Ongoing chain

Every reply repeats the same pattern:

- consume received `reply_drop`
- generate fresh new `reply_drop`
- encrypt payload
- upload to recipient's last `reply_drop`

---

## 16. Polling model

V1 uses client polling, not push.

A client MAY poll:

- on app start
- on manual refresh
- periodically, e.g. every 10 to 30 seconds

### Recommended V1 behavior

- Desktop CLI/manual mode: explicit command invocation is acceptable
- Desktop/mobile GUI: periodic polling is acceptable
- Browser clients: periodic polling is acceptable if CORS is supported

---

## 17. Error handling

### 17.1 HTTP-layer errors

#### `201 Created`
Upload succeeded.

#### `400 Bad Request`
Malformed JSON or invalid envelope shape.

#### `404 Not Found`
No message exists for the requested drop.

#### `409 Conflict`
The drop has already been used.

#### `413 Payload Too Large`
Envelope exceeds server maximum size.

#### `5xx`
Server error. Client may retry according to policy.

---

### 17.2 Client-side states

Each outbound message SHOULD be tracked as one of:

- `pending`
- `sent`
- `failed`

Optional extra state:

- `delivered_to_drop`

In V1, `PUT` success means only that the envelope was stored, not that the recipient read it.

---

### 17.3 Duplicate handling

Clients SHOULD store seen `msg_id` values and ignore duplicates.

Recommended rule:

- if `msg_id` has already been processed for a conversation, do not reinsert it into history

---

### 17.4 Decryption failures

If decryption fails, the client SHOULD:

- mark the envelope as invalid/unreadable
- avoid crashing
- allow diagnostic logging
- not assume sender authenticity

---

## 18. Security considerations

### 18.1 Drop ID entropy

Drop IDs are the primary capability in V1.  
They MUST be generated using a cryptographically secure RNG.

Recommended size:

- 32 random bytes, base64url-encoded

### 18.2 Server abuse

Open drop servers can be abused.  
Servers SHOULD consider:

- request size limits
- IP rate limits
- TTL cleanup
- abuse detection

### 18.3 Metadata leakage

Servers can observe:

- source IP address of uploaders
- target drop IDs
- upload time
- approximate message size
- read/poll timing

V1 does not solve this.

### 18.4 Malicious servers

Servers may:

- drop messages
- refuse writes
- refuse reads
- delay requests
- log metadata

Clients should not trust server availability.

### 18.5 Authenticity limitations

V1 provides encrypted communication but does not define strong signature-based sender authentication inside each message.  
Identity binding relies partly on the contact bundle and correct decryption relationship.

A future version may add signed envelopes.

---

## 19. Interoperability requirements

Two implementations are interoperable if they agree on:

1. JSON schema described in this spec
2. base64url encoding rules
3. HTTP endpoint semantics
4. chosen cryptographic suite

### Mandatory shared suite for V1 interoperability

To keep implementations compatible, Codex SHOULD implement this exact suite first:

- Ed25519 for identity keys
- X25519 for prekeys and ephemeral keys
- HKDF-SHA256 for key derivation
- ChaCha20-Poly1305 for payload encryption

---

## 20. Recommended file formats for local storage

This section is non-normative but recommended.

### 20.1 Identity file

```json
{
  "v": 1,
  "display_name": "Alice",
  "identity_secret_key": "BASE64URL...",
  "identity_public_key": "BASE64URL...",
  "prekey_secret_key": "BASE64URL...",
  "prekey_public_key": "BASE64URL..."
}
```

### 20.2 Contacts file

```json
{
  "v": 1,
  "contacts": [
    {
      "contact_id": "base64url-random",
      "display_name": "Bob",
      "identity_key": "ed25519:BASE64URL...",
      "prekey": "x25519:BASE64URL...",
      "initial_drops": [
        {
          "server": "https://drop1.example.org",
          "drop_id": "..."
        }
      ]
    }
  ]
}
```

### 20.3 Messages file

```json
{
  "v": 1,
  "messages": [
    {
      "msg_id": "....",
      "contact_id": "....",
      "direction": "outbound",
      "created_at": 1777000100,
      "text": "Hello",
      "status": "sent",
      "used_drop": {
        "server": "https://drop1.example.org",
        "drop_id": "..."
      },
      "reply_drop_generated": {
        "server": "https://drop2.example.org",
        "drop_id": "..."
      }
    }
  ]
}
```

---

## 21. Recommended implementation split

This section is intended for Codex.

### 21.1 Server responsibilities

The server should:

- implement a very small HTTPS or HTTP API
- store JSON blobs by `drop_id`
- reject overwrites
- support `PUT`, `GET`, `HEAD`
- use SQLite or flat-file/KV storage
- optionally support TTL cleanup on startup or periodic sweep

### 21.2 Client responsibilities

The client should:

- manage local keys
- manage local contacts
- create/import/export contact bundles
- create random drops on configured servers
- send encrypted messages
- fetch and decrypt messages
- store message history locally

---

## 22. Suggested CLI commands for a reference client

This section is non-normative but recommended for the first implementation.

### Identity management

- `linkdrop init --name "Alice"`
- `linkdrop whoami`

### Contact management

- `linkdrop contact export --server https://drop1.example.org --server https://drop2.example.org`
- `linkdrop contact import <bundle-file>`
- `linkdrop contacts list`

### Messaging

- `linkdrop send --to <contact-id> --text "hello"`
- `linkdrop poll`
- `linkdrop inbox`
- `linkdrop history --contact <contact-id>`

---

## 23. Suggested server storage schema

### SQLite example

```sql
CREATE TABLE drops (
    drop_id TEXT PRIMARY KEY,
    body BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_drops_created_at ON drops(created_at);
```

### Storage rules

- `drop_id` is unique
- insert fails if already present
- `body` stores the raw JSON request body
- TTL cleanup deletes rows older than configured threshold

---

## 24. Minimal compliance test cases

Codex should implement at least these tests.

### 24.1 Server tests

1. `PUT` to unused drop returns `201`
2. second `PUT` to same drop returns `409`
3. `GET` to used drop returns stored body
4. `GET` to unused drop returns `404`
5. `HEAD` to used drop returns `200`
6. `HEAD` to unused drop returns `404`

### 24.2 Client tests

1. identity generation succeeds
2. contact bundle export/import round-trips
3. message encryption/decryption round-trips
4. fresh reply drop is generated for each outbound message
5. duplicate `msg_id` is ignored
6. send to valid initial drop succeeds end-to-end using a local server

---

## 25. Example objects

### 25.1 Contact bundle example

```json
{
  "v": 1,
  "display_name": "Bob",
  "identity_key": "ed25519:MCowBQYDK2VwAyEAexample",
  "prekey": "x25519:MCowBQYDK2VuAyEAexample",
  "initial_drops": [
    {
      "server": "https://drop1.example.org",
      "drop_id": "m0z7M7U4dP7v8a5i4mM5Lw"
    }
  ]
}
```

### 25.2 Envelope example

```json
{
  "v": 1,
  "msg_id": "fQ9lX4rY9B2o0nN8",
  "created_at": 1777000100,
  "reply_drop": {
    "server": "https://drop2.example.org",
    "drop_id": "qB1r8P3nZ6cW2sK9"
  },
  "sender_identity_key": "ed25519:MCowBQYDK2VwAyEAalice",
  "sender_ephemeral_key": "x25519:MCowBQYDK2VuAyEAephemeral",
  "ciphertext": "BASE64URL_CIPHERTEXT",
  "nonce": "BASE64URL_NONCE"
}
```

### 25.3 Payload example

```json
{
  "text": "Hej",
  "prev_msg_id": "optional"
}
```

---

## 26. Implementation requirements for Codex

Codex should implement exactly this V1.

### 26.1 Server

Implement a Rust drop server with:

- `PUT /drop/{drop_id}`
- `GET /drop/{drop_id}`
- `HEAD /drop/{drop_id}`
- SQLite backend
- max body size config
- TTL cleanup
- no auth
- JSON body passthrough

### 26.2 Client

Implement a Rust CLI client with:

- local identity generation
- contact bundle export
- contact bundle import
- configured list of drop servers
- send text message to contact
- poll for messages
- local JSON or SQLite state store
- exact crypto suite defined above

### 26.3 Suggested Rust crates

Non-normative suggestion:

- `axum` or `hyper` for server
- `reqwest` for HTTP client
- `rusqlite` for SQLite
- `serde`, `serde_json`
- `rand`
- `base64`
- `ed25519-dalek`
- `x25519-dalek`
- `chacha20poly1305`
- `hkdf`
- `sha2`
- `clap`

---

## 27. Explicit exclusions for first implementation

To prevent scope creep, Codex should NOT implement in the first pass:

- groups
- attachments
- push
- WebRTC
- relay discovery
- direct node hosting
- signature framework
- read receipts
- multi-device
- contact syncing
- server federation
- automatic key rotation beyond initial setup

---

## 28. Future extensions

Out of scope for V1, but compatible with the architecture:

- reply drop inside ciphertext
- signed envelopes
- multiple prekeys / prekey rotation
- richer payload types
- attachments via external blob store
- relay redundancy
- client-owned nodes
- WebRTC transport when both peers are online
- server directory/discovery
- onion-style routing or metadata-reduction layers

---

## 29. Normative summary

The following statements are normative.

- A drop server MUST allow at most one successful write per `drop_id`.
- A client MUST generate cryptographically random drop IDs.
- A message envelope MUST include exactly one `reply_drop`.
- A client MUST generate a fresh reply drop for every outgoing message.
- A contact bundle MUST contain at least one initial drop.
- Message payloads MUST be encrypted before upload.
- A compliant V1 implementation MUST support the mandatory cryptographic suite defined in Section 19.
- A drop server MUST support `PUT`, `GET`, and `HEAD` on `/drop/{drop_id}`.
- A drop server MUST NOT require user accounts for basic V1 operation.

---

## 30. One-sentence protocol summary

**Linkdrop V1 is a minimal encrypted messaging protocol where users exchange contact bundles containing single-use initial drops, and each message advances the conversation by carrying a fresh reply drop for the next response.**
