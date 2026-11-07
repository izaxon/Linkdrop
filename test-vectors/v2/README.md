# Linkdrop V2 draft test vectors

[`normative.json`](normative.json) is the interoperability target for the **draft** wire version `v: 2` described in [`linkdrop-v2-spec.md`](../../linkdrop-v2-spec.md). While the draft is open these bytes may change together with the specification; once V2 is frozen they become immutable under [COMPATIBILITY.md](../../COMPATIBILITY.md).

It contains:

- one valid V2 contact bundle with the owner's signing secret and the initial capability's one-time X25519 secret;
- three complete messages, each with fixed receive secret, sender signing secret, sender ephemeral secret, and nonce:
  - `capability_message`: Alice → Bob on the bundle's initial capability (seq 0), carrying Alice's receive profile and rescue;
  - `chain_message`: Bob → Alice on a derived drop of Alice's profile (seq 0, `ack: 0`, rotating Alice → Bob to generation 1);
  - `control_message`: Alice → Bob control message with `ack`, `missing`, and `resend_of`, which pins the transcript encoding of every optional member;
- for each message: the X25519 shared secret, the HKDF message-key inputs and output, the exact plaintext UTF-8 bytes, the binary signature transcript, the Ed25519 signature, nonce, ciphertext with appended tag, and the public envelope;
- the implied generation-0 chain key derived from the capability message;
- two derived-drop tables (`drop_id` and server for `seq` 0–3) for the implied generation and for an explicit receive profile;
- invalid contact bundles, envelopes, payload contents, and a tampered in-ciphertext signature.

All base64url values are unpadded. HKDF for drop IDs uses no salt; HKDF for chain and message keys uses the raw drop-ID bytes as salt. AEAD associated data is empty.

## Regenerating

```bash
cargo run -p linkdrop-protocol --example gen_v2_vectors > test-vectors/v2/normative.json
```

The generator uses only fixed byte patterns, so the output is reproducible. Regenerate only together with a specification change and a changelog entry.

## Security warning

Every secret and nonce in this file is public and deterministic. Never use them in a real message.

## Conformance

A V2 implementation should:

1. parse and validate the bundle, the three payloads, and the three envelopes;
2. reproduce each shared secret and message key;
3. reproduce the implied chain key and both derived-drop tables;
4. reproduce each plaintext serialization, transcript, signature, and ciphertext/tag;
5. decrypt each public envelope to the listed payload and verify the signature;
6. fail to decrypt the capability envelope under another drop ID; and
7. reject every invalid case at validation or signature verification.

The Rust test `crates/linkdrop-protocol/tests/protocol_vectors_v2.rs` exercises this file directly.
