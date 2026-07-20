# Phase A protocol-boundary audit

Date: 2026-07-20  
Sources compared: `linkdrop-v1-spec.md`, protocol models and crypto, CLI behavior, server behavior, README, AGENTS.md, and all Rust tests.

The decision is to freeze the already-emitted encrypted-`reply_drop` layout as corrected V1. This is limited to the previously unfrozen draft. Future incompatible work uses a new integer version.

| # | Incompatibility or ambiguity | Evidence before freeze | Phase A resolution | Class |
| --- | --- | --- | --- | --- |
| 1 | Reply-drop location disagreed. | Spec §§5, 7.3, 9.4, 29 required public `reply_drop`; `DecryptedPayload` and tests encrypted it. | V1 requires it inside ciphertext and forbids it at envelope top level. | Pre-freeze documentation correction |
| 2 | The overview/diagram exposed a reply drop while prose later said it was encrypted. | README diagram used `PUT { reply_drop, ciphertext }`; implementation notes said encrypted. | Diagram and prose now show one layout only. | Documentation correction |
| 3 | Signatures were simultaneously out of scope and implemented/default. | Spec §§9.5, 27, 28 excluded signatures; model has `signature`; CLI defaults to signed; tests require both modes. | Optional Ed25519 signatures are frozen; unsigned remains valid. | Pre-freeze documentation correction |
| 4 | Signature bytes were unspecified and serialization-order dependent. | Rust signs compact reserialization of known struct fields with `signature=None`. | Exact ordered compact JSON transcript is normative and vectorized. | Documentation correction; V2 should use a stronger canonical transcript |
| 5 | Unknown JSON fields had no policy and were excluded from signatures. | Serde accepts/drops unknown members before transcript reserialization. | Consumers ignore unknown V1 fields; they are explicitly unauthenticated and carry no meaning. | Ambiguity resolved |
| 6 | Required crypto suite was contradictory. | Spec §9 said recommended choices and allowed AES-GCM; §19 named ChaCha20-Poly1305 with SHOULD. | One mandatory V1 suite is specified. | Documentation correction |
| 7 | HKDF salt was “optional” and therefore non-interoperable. | Rust uses `Hkdf::new(None, shared_secret)` and fixed info. | Absent salt, exact info, and 32-byte output are normative and vectorized. | Documentation correction |
| 8 | AEAD associated data and tag layout were omitted. | Rust passes no AAD and base64url-encodes ciphertext plus tag. | Empty AAD, 12-byte nonce, and appended 16-byte tag are normative. | Documentation correction |
| 9 | Low-order X25519 handling was unstated. | Validation checks only tag and 32-byte length. | Frozen V1 records that no separate rejection rule exists; redesign is deferred. | Security ambiguity documented |
| 10 | The stable public sender identity contradicted unlinkability claims. | Envelope exposes a reused Ed25519 key; README said a server cannot link conversations. | Claims are narrowed: content is hidden, but a server can correlate that key. | Security claim correction |
| 11 | Signature verification was not bound to the expected contact. | Crypto verifies the key carried in the same envelope; CLI selects a watched contact without equality enforcement. | Self-asserted authenticity limitation is explicit; expected-contact binding is deferred. | Security gap deferred |
| 12 | Unsigned messages were accepted without a clear trust meaning. | CLI/test accepts them and records `Unsigned`. | Absence is valid V1; it provides only AEAD integrity, not signed authorship. | Ambiguity resolved |
| 13 | A one-way bundle was presented as enough for a conversation. | Reply drop has no recipient key; sending requires the other party's long-term prekey; end-to-end test exchanges both bundles. | V1 explicitly requires both prekeys before a bidirectional exchange. | Product/protocol limitation documented |
| 14 | Forward-secrecy language was vague. | Each sender key is ephemeral, but all messages target a long-term recipient prekey. | V1 explicitly lacks secrecy after recipient-prekey compromise. | Security claim correction |
| 15 | HTTPS rules contradicted local behavior. | Spec required HTTPS everywhere; code/tests accept HTTP loopback; README/AGENTS mentioned the exception. | Normative loopback-only development exception is specified. | Documentation correction |
| 16 | “Origin or base URL” did not define path construction. | CLI preserves a base path, ensures a slash, then joins `drop/{id}`. | Base-path resolution is specified; query/fragment have no role. | Ambiguity resolved |
| 17 | Identifier constraints were incomplete. | Model accepts non-empty base64url `msg_id`, generates 16 bytes; drop IDs validate 16+ and generate 32; `prev_msg_id` validates non-empty. | Exact accepted/generated behavior is stated and vectorized. | Ambiguity resolved |
| 18 | Empty text validity disagreed. | Draft called text UTF-8 but did not forbid empty; model/CLI reject empty. | V1 text is non-empty. | Pre-freeze documentation correction |
| 19 | Timestamp validation was unspecified. | Model accepts any `i64` and performs no freshness check. | Signed Unix seconds with no V1 freshness window is explicit. | Ambiguity resolved |
| 20 | Unknown version behavior was not consistently separated from local state versions. | Wire and JSON state files all use fields named `v`. | Unsupported wire versions are rejected; local-state versions are implementation-specific. | Ambiguity resolved |
| 21 | Server validation scope was vague. | Server parses `MessageEnvelope` and validates known fields, but treats URL path `drop_id` as opaque. | Envelope validation and client-owned drop-ID entropy checks are separated. | Ambiguity resolved |
| 22 | Content-Type requirement was phrased as request shape, while the server does not enforce it. | Server reads raw bytes regardless of header. | Clients send JSON content type; envelope validity and status behavior are normative. Header enforcement is not claimed. | Implementation detail documented |
| 23 | Storage wording allowed exact or “normalized equivalent.” | Rust stores exact request bytes. | V1 server behavior specifies exact stored request bytes. | Ambiguity resolved |
| 24 | Invalid and duplicate messages consume watched drops in the CLI. | Poll/process code removes a fetched watch; duplicate check precedes crypto verification. | Recorded as reference behavior, not a wire invariant; crash-safe state work is deferred. | Client hardening deferred |
| 25 | Polling failure isolation was unspecified. | One server error aborts the whole Rust poll loop. | Recorded as a known reference limitation; per-drop continuation is deferred. | Client hardening deferred |
| 26 | Send and state writes were presented without failure semantics. | Drop selection mutates memory before PUT; JSON files are non-atomic; no durable outbox. | Security/operations limits are explicit; transactional state is deferred. | Client hardening deferred |
| 27 | TTL wording could imply continuous cleanup. | Server config has TTL but cleanup runs only at startup. | V1 only recommends expiry; periodic cleanup remains issue #1 server hardening. | Server hardening deferred |
| 28 | “Zero dependencies” was false/ambiguous. | Rust uses normal crates; the intended claim was no provider/account/SDK/central service. | Documentation uses the precise infrastructure-independence claim. | Documentation correction |
| 29 | Rust edition documentation was stale. | AGENTS.md said 2021; workspace manifests use 2024. | AGENTS.md now says Rust 2024. | Documentation correction |
| 30 | “Spec wins” was unsafe while the draft contradicted tested code. | AGENTS.md made the stale draft normative. | Spec, changelog, policy, vectors, models, and tests now form one boundary; discrepancies must stop wire changes. | Process correction |
| 31 | There was no compatibility or freeze policy. | No changelog, vector immutability rule, or version-bump criteria. | Added protocol changelog and compatibility policy. | Process addition |
| 32 | Examples used placeholder key encodings that were not valid vectors. | Old examples such as `MCow...example` did not decode to required raw key sizes. | Examples are copied from deterministic normative vectors. | Documentation correction |

## Deliberately unchanged cryptography

Phase A does not move sender identity into ciphertext, introduce one-time recipient keys, bind a signature to the consumed drop/contact, add associated data, or change the KDF. Those are protocol-breaking changes and must not be smuggled into the meaning of `v: 1`.

## Deferred roadmap work

Issue #1 remains authoritative for one-time encrypted capabilities, identity binding, crash-safe client state, server hardening, a second implementation, fuzz/property testing, and demonstrations. Browser UI, bots, attachments, groups, and push are explicitly outside this pull request.
