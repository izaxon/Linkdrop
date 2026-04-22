# Linkdrop User Manual

Linkdrop is a small Rust-based messaging system built around **drop URLs**. A sender writes one encrypted message to a specific drop, and the recipient polls the drops they are watching. The workspace contains:

- `linkdrop` - the command-line client
- `linkdrop-server` - the HTTP/SQLite drop server

This manual covers installation, first-time setup, everyday usage, local state files, server operation, and troubleshooting.

## 1. What Linkdrop does

Linkdrop lets two users exchange encrypted messages without keeping a long-lived session on the server.

At a high level:

1. Each user creates a local identity.
2. Each user exports a **contact bundle** containing public identity material and one or more initial drops.
3. The other side imports that bundle as a contact.
4. Messages are sent to the contact's current drop.
5. Each message carries the **next reply drop inside the encrypted payload**, so the conversation can continue.

Current implementation details:

- Message payloads are encrypted with **X25519 + HKDF-SHA256 + ChaCha20-Poly1305**
- Envelopes may be **signed with Ed25519**
- Signed sends are the default
- The CLI can keep a list of **preferred servers** and rotate reply drops across them
- HTTP is accepted only for localhost-style development URLs; non-local deployments should use HTTPS

## 2. Requirements

- Rust and Cargo
- A shell environment that can run two processes if you want to test locally:
  - `linkdrop-server`
  - `linkdrop`

## 3. Building and installing

### Build the workspace

```bash
cargo build
```

### Run the test suite

```bash
cargo test
```

### Run binaries without installing

```bash
cargo run -p linkdrop-server -- --help
cargo run -p linkdrop-cli --bin linkdrop -- --help
```

### Optional: install the binaries

```bash
cargo install --path crates/linkdrop-server
cargo install --path crates/linkdrop-cli
```

After that, the binaries are typically available as:

- `linkdrop-server`
- `linkdrop`

## 4. Quick start

This example starts one local server and uses separate state directories for Alice and Bob.

### Start the server

```bash
cargo run -p linkdrop-server -- --bind 127.0.0.1:8080 --database linkdrop-server.db
```

### Initialize Alice and Bob

```bash
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice init --name Alice
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob init --name Bob
```

### Add a preferred server for both users

```bash
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice server add --url http://127.0.0.1:8080
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob server add --url http://127.0.0.1:8080
```

### Export contact bundles

```bash
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice contact export > alice-bundle.json
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob contact export > bob-bundle.json
```

### Import each other

```bash
ALICE_CONTACT_IN_BOB=$(cargo run -q -p linkdrop-cli --bin linkdrop -- --state-dir .bob contact import alice-bundle.json)
BOB_CONTACT_IN_ALICE=$(cargo run -q -p linkdrop-cli --bin linkdrop -- --state-dir .alice contact import bob-bundle.json)
```

The `contact import` command prints the generated local `contact_id`. You use that ID for `send` and `history`.

### Send a message from Alice to Bob

```bash
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice send --to "$BOB_CONTACT_IN_ALICE" --text "hello bob"
```

The command prints the new `msg_id`.

### Bob polls and reads inbox

```bash
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob poll
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob inbox
```

### Bob replies, then Alice polls

```bash
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .bob send --to "$ALICE_CONTACT_IN_BOB" --text "hello alice"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice poll
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .alice history --contact "$BOB_CONTACT_IN_ALICE"
```

## 5. Command reference

Top-level help:

```text
Usage: linkdrop [OPTIONS] <COMMAND>

Commands:
  init
  whoami
  contact
  contacts
  send
  poll
  inbox
  history
  server
```

Global option:

- `--state-dir <STATE_DIR>` - directory used for local identity, contacts, client state, and message history; default: `.linkdrop`

### 5.1 `init`

Create a new local identity and initialize the state directory.

```bash
linkdrop --state-dir .linkdrop init --name "Alice"
```

Behavior:

- Fails if the name is empty or whitespace
- Creates:
  - `identity.json`
  - `contacts.json`
  - `messages.json`
  - `client.json`
- Prints `initialized`

### 5.2 `whoami`

Show the current user's public-facing identity values.

```bash
linkdrop --state-dir .linkdrop whoami
```

Output format:

```text
display_name: Alice
identity_key: ed25519:...
prekey: x25519:...
```

This command does **not** print secret keys.

### 5.3 `contact export`

Export a contact bundle as JSON.

```bash
linkdrop --state-dir .linkdrop contact export --server https://example.com
```

You may repeat `--server`:

```bash
linkdrop --state-dir .linkdrop contact export \
  --server https://s1.example.com \
  --server https://s2.example.com
```

If you omit `--server`, the command uses preferred servers previously added with `server add`.

Important behavior:

- At least one server must be available, either through `--server` or the preferred server list
- Each exported server receives a fresh initial drop
- Export also registers those drops in local `client.json` as watched drops
- The command prints the bundle JSON to stdout

Typical usage:

```bash
linkdrop --state-dir .linkdrop contact export > my-bundle.json
```

### 5.4 `contact import`

Import another user's contact bundle from disk.

```bash
linkdrop --state-dir .linkdrop contact import alice-bundle.json
```

Behavior:

- Validates the bundle
- Creates a new local `contact_id` if this identity is new
- Updates the existing contact if the identity already exists
- Stores the contact in `contacts.json`
- Prints the local `contact_id`

The printed `contact_id` is local to your state directory. Another user will usually have a different `contact_id` for the same person.

### 5.5 `contacts list`

List all contacts known in the current state directory.

```bash
linkdrop --state-dir .linkdrop contacts list
```

Output format:

```text
<contact_id>    <display_name>    initial_drops=<N>    next=<server#drop_prefix| ->
```

Notes:

- `initial_drops` is the number of unused initial drops still available
- `next` shows the next reply drop to use when one has already been learned from a received message
- If no contacts exist, output is `no contacts`

### 5.6 `send`

Send an encrypted message to a contact.

```bash
linkdrop --state-dir .linkdrop send --to <contact_id> --text "hello"
```

Unsigned interoperability send:

```bash
linkdrop --state-dir .linkdrop send --to <contact_id> --text "interop" --unsigned
```

Behavior:

- Fails if the message text is empty or whitespace
- Uses `next_outgoing_drop` if available; otherwise consumes one of the contact's `initial_drops`
- Requires the contact to have a `prekey`
- Generates a fresh reply drop for the recipient to use
- Stores an outbound record in `messages.json`
- Prints the new `msg_id`

Signing behavior:

- Default: signed envelope
- `--unsigned`: no signature is attached

Result handling:

- HTTP `201`: message recorded as `sent`
- HTTP `409`: drop already used; message recorded as `failed`
- HTTP `400`: invalid envelope; command fails
- HTTP `404`: missing drop endpoint; command fails
- HTTP `413`: payload too large; command fails
- HTTP `5xx`: message recorded as `failed`

### 5.7 `poll`

Check watched drops for incoming messages.

```bash
linkdrop --state-dir .linkdrop poll
```

Output:

- `poll complete: no new messages`
- or `poll complete: received X, duplicates Y, invalid Z`

Behavior:

- Polls each watched drop with `HEAD` first, then `GET` if present
- Decrypts readable messages and appends them to `messages.json`
- Sets the contact's `next_outgoing_drop` from the decrypted payload
- Marks unreadable or tampered messages as `invalid`
- Deduplicates by `msg_id` per contact

### 5.8 `inbox`

Show inbound messages only.

```bash
linkdrop --state-dir .linkdrop inbox
```

If there are no inbound messages, output is `no messages`.

### 5.9 `history`

Show all recorded messages for one contact.

```bash
linkdrop --state-dir .linkdrop history --contact <contact_id>
```

If there is no history for that contact, output is `no messages`.

### 5.10 `server add`

Add a preferred server URL.

```bash
linkdrop --state-dir .linkdrop server add --url https://example.com
```

Behavior:

- Validates the URL
- Stores it in `client.json`
- Does not add duplicates
- Prints `added`

### 5.11 `server list`

Show preferred servers.

```bash
linkdrop --state-dir .linkdrop server list
```

If none are configured, output is `no preferred servers`.

## 6. Understanding message and contact flow

### Initial contact

Before a first message can be sent, you need:

1. Your identity initialized with `init`
2. At least one server
3. A contact bundle exported by the remote party
4. That bundle imported into your local contact list

### Ongoing conversation

For the first send, the client uses one of the contact's `initial_drops`.

For later sends, the client prefers `next_outgoing_drop`, which it learns only after receiving and decrypting a message from that contact.

### Why polling matters

Polling does more than fetch text. It also updates the conversation state by extracting the next reply drop from the encrypted payload. If you never poll, your local state will not learn the next drop for replies.

## 7. Output formats

### `contacts list`

Example:

```text
A4n9empOtt_3dfUM	Bob	initial_drops=1	next=-
```

### `inbox`

Example:

```text
1776846503	<-	Alice	Inbound,Received,Verified	hello bob
```

### `history`

Example:

```text
1776846503	->	Bob	Outbound,Sent,Signed	hello bob
1776846504	<-	Bob	Inbound,Received,Verified	hello alice
```

Field meanings:

- first field - Unix timestamp from the envelope
- arrow - `->` outbound, `<-` inbound
- contact name - display name if known, otherwise `contact_id`
- metadata triplet - direction, message status, signature state
- final field - message text

## 8. State directory layout

By default the client uses `.linkdrop`, but you can set any directory with `--state-dir`.

Files:

- `identity.json` - your local identity, including secret keys
- `contacts.json` - imported contacts and their current drop state
- `client.json` - watched drops, preferred servers, and server rotation index
- `messages.json` - local message history and delivery/decryption results

### 8.1 `identity.json`

Purpose:

- Stores your display name
- Stores your Ed25519 identity keypair
- Stores your X25519 prekey pair

Security note:

- This file contains **secret keys**
- Treat it like a private credential
- Do not commit it to version control
- Do not share it

### 8.2 `contacts.json`

Each contact record may contain:

- `contact_id`
- `display_name`
- `identity_key`
- `prekey`
- `initial_drops`
- `next_outgoing_drop`

Interpretation:

- `initial_drops` are one-time starting points from the imported bundle
- `next_outgoing_drop` is learned from an inbound message and becomes the preferred drop for the next outbound send

### 8.3 `client.json`

Contains:

- `watched_drops` - drops this client should poll
- `preferred_servers` - server list used by `contact export` and reply-drop rotation
- `next_server_index` - round-robin pointer for preferred server rotation

### 8.4 `messages.json`

Each message record tracks:

- `msg_id`
- `contact_id`
- `direction`
- `created_at`
- `text`
- `status`
- drop references used for send/receive
- optional `prev_msg_id`
- `signature_state`

Message statuses:

- `sent` - send succeeded
- `failed` - send reached the server but was not accepted for reuse/conflict or server-side failure conditions that are recorded
- `received` - inbound message was decrypted successfully
- `invalid` - inbound message could not be decrypted or failed validation after fetch

Signature states:

- `unsigned` - no signature was attached
- `signed` - this client created a signed outbound message
- `verified` - inbound signature verified
- `invalid` - inbound signature or message integrity was not acceptable

## 9. Contact bundle format

A contact bundle is JSON with:

- `v`
- `display_name`
- `identity_key`
- `prekey`
- `initial_drops`

Example shape:

```json
{
  "v": 1,
  "display_name": "Alice",
  "identity_key": "ed25519:...",
  "prekey": "x25519:...",
  "initial_drops": [
    {
      "server": "https://example.com",
      "drop_id": "..."
    }
  ]
}
```

Validation rules of note:

- `v` must be `1`
- `identity_key` must be tagged `ed25519:...`
- `prekey` must be tagged `x25519:...`
- At least one initial drop is required

## 10. Running the server

Top-level help:

```text
Usage: linkdrop-server [OPTIONS]

Options:
      --bind <BIND>                    [default: 127.0.0.1:8080]
      --database <DATABASE>            [default: linkdrop-server.db]
      --max-body-size <MAX_BODY_SIZE>  [default: 16384]
      --ttl-seconds <TTL_SECONDS>      [default: 604800]
```

### Basic usage

```bash
linkdrop-server --bind 127.0.0.1:8080 --database linkdrop-server.db
```

### What the server stores

The server stores message envelopes in SQLite:

- one row per `drop_id`
- raw JSON request body
- creation timestamp

### HTTP API

The server exposes:

- `PUT /drop/{drop_id}` - write a message envelope once
- `GET /drop/{drop_id}` - fetch the stored envelope
- `HEAD /drop/{drop_id}` - check whether a drop exists

### Server semantics

- A drop ID can be written only once
- A second `PUT` to the same drop returns `409 Conflict`
- `GET` and `HEAD` return `404 Not Found` for unknown drops
- `GET` returns `application/json` when a drop exists
- Request bodies larger than `--max-body-size` are rejected with `413 Payload Too Large`
- Invalid JSON or invalid envelope structure is rejected with `400 Bad Request`

### TTL behavior

The server has a configurable `--ttl-seconds` value. Expired drops are cleaned up when the server starts.

Default TTL:

- `604800` seconds
- 7 days

## 11. Local development notes

- Localhost HTTP URLs such as `http://127.0.0.1:8080` are accepted for development
- For non-local deployments, use HTTPS-style server URLs
- The CLI is blocking and file-based, which makes it easy to test with multiple state directories

## 12. Common workflows

### Use one state directory per person

```bash
linkdrop --state-dir .alice ...
linkdrop --state-dir .bob ...
```

This is the easiest way to test multiple identities on one machine.

### Re-export after changing preferred servers

If you want newly shared bundles to contain a different set of initial drops, update preferred servers first:

```bash
linkdrop --state-dir .linkdrop server add --url https://s1.example.com
linkdrop --state-dir .linkdrop server add --url https://s2.example.com
linkdrop --state-dir .linkdrop contact export > my-bundle.json
```

### Share bundles as files

The simplest exchange flow is:

1. Export bundle to a file
2. Deliver the file out of band
3. Import it on the other side

## 13. Troubleshooting

### `at least one --server value is required, or add a preferred server first`

Cause:

- You ran `contact export` without `--server` and without any preferred servers

Fix:

```bash
linkdrop --state-dir .linkdrop server add --url https://example.com
```

or pass `--server` directly to `contact export`.

### `contact <id> not found`

Cause:

- `send` or `history` used a local `contact_id` that does not exist in this state directory

Fix:

- Run `contacts list`
- Use the correct local `contact_id`

### `contact <id> has no prekey; import their contact bundle first`

Cause:

- The contact record is incomplete or stale

Fix:

- Import a valid bundle for that contact again

### `contact <id> has no available drop to send to`

Cause:

- All imported initial drops have been used and no reply drop has been learned yet

Fix:

- Get a fresh contact bundle from the remote user, or wait until you receive a message that carries a new reply drop

### `failed to send message to ...` with connection errors

Cause:

- The server is not running, not reachable, or the URL is wrong

Fix:

- Start `linkdrop-server`
- Confirm `--bind` matches the URL you stored
- Re-check host, port, and protocol

### `server rejected the envelope because it was too large`

Cause:

- The encoded JSON body exceeded `--max-body-size`

Fix:

- Reduce message size or start the server with a larger limit

### `poll complete: no new messages`

This means:

- No watched drop currently exists on the server, or
- The watched drops were not populated for the message you expected

Check:

- That the other user actually sent the message
- That you exported and imported bundles correctly
- That your `client.json` still contains the relevant watched drops

## 14. Security and handling notes

- Protect `identity.json`; it contains secret keys
- Treat contact bundles as public-shareable contact data, not secret identity material
- Prefer signed messages unless you are deliberately testing interoperability with `--unsigned`
- Use HTTPS for non-local servers
- Avoid storing real user data in development state directories

## 15. Practical reference

### Minimal local setup

```bash
cargo run -p linkdrop-server -- --bind 127.0.0.1:8080 --database linkdrop-server.db
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop init --name "Alice"
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop server add --url http://127.0.0.1:8080
cargo run -p linkdrop-cli --bin linkdrop -- --state-dir .linkdrop contact export
```

### Full conversation loop

```bash
linkdrop --state-dir .alice init --name Alice
linkdrop --state-dir .bob init --name Bob

linkdrop --state-dir .alice server add --url http://127.0.0.1:8080
linkdrop --state-dir .bob server add --url http://127.0.0.1:8080

linkdrop --state-dir .alice contact export > alice-bundle.json
linkdrop --state-dir .bob contact export > bob-bundle.json

ALICE_CONTACT_IN_BOB=$(linkdrop --state-dir .bob contact import alice-bundle.json)
BOB_CONTACT_IN_ALICE=$(linkdrop --state-dir .alice contact import bob-bundle.json)

linkdrop --state-dir .alice send --to "$BOB_CONTACT_IN_ALICE" --text "hello bob"
linkdrop --state-dir .bob poll
linkdrop --state-dir .bob inbox

linkdrop --state-dir .bob send --to "$ALICE_CONTACT_IN_BOB" --text "hello alice"
linkdrop --state-dir .alice poll
linkdrop --state-dir .alice history --contact "$BOB_CONTACT_IN_ALICE"
```
