# Linkdrop V1 normative test vectors

[`normative.json`](normative.json) is part of the frozen V1 interoperability contract.

It contains:

- one valid contact bundle;
- fixed Ed25519, X25519, nonce, and identifier inputs;
- the X25519 shared secret;
- exact HKDF-SHA256 salt/info/output;
- exact decrypted-payload UTF-8 bytes;
- ChaCha20-Poly1305 ciphertext with its appended tag;
- the exact compact signature transcript and Ed25519 signature;
- a valid signed public envelope;
- invalid contact-bundle, envelope, payload, and signature cases.

All base64url values are unpadded. `salt: null` means no explicit HKDF salt, i.e. the RFC 5869 all-zero HashLen default. AEAD associated data is empty.

## Security warning

The private keys and nonce are intentionally deterministic and public. They exist only to make independent implementations reproduce the same bytes. Never use them in a real message.

## Conformance

A V1 implementation should:

1. parse and validate the valid contact and envelope;
2. reproduce the shared secret and KDF key;
3. reproduce the plaintext serialization and ciphertext/tag;
4. reproduce and verify the signature transcript;
5. decrypt the public envelope to the listed payload; and
6. reject every invalid case at validation, decryption, or signature verification as appropriate.

The Rust test `crates/linkdrop-protocol/tests/protocol_vectors.rs` exercises this file directly.
