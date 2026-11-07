# Protocol compatibility policy

## Scope

Wire compatibility covers `ContactBundle`, `DropRef`, `MessageEnvelope`, decrypted payload JSON, cryptographic transcripts and inputs, and drop-server HTTP semantics. Rust crate versions, CLI flags, and local state-file versions are separate.

## Frozen versions

A frozen version is defined by its specification and normative test vectors. For V1 those are [linkdrop-v1-spec.md](linkdrop-v1-spec.md) and [test-vectors/v1](test-vectors/v1).

Frozen versions may receive editorial clarifications, new non-normative examples, additional failure vectors, and security warnings only when they do not change accepted or emitted wire meaning.

## Draft versions

A draft version has an integer `v`, a specification marked `Status: Draft`, and vectors that are the current interoperability target but may change together with the specification. V2 is a draft: [linkdrop-v2-spec.md](linkdrop-v2-spec.md) and [test-vectors/v2](test-vectors/v2).

While a version is a draft:

- its wire bytes MAY change, but every change updates the specification, the vectors, and the changelog in the same change;
- it MUST NOT alter the meaning, validation, or emitted bytes of any frozen version;
- a reference implementation MUST select it only by its explicit `v` value and MUST keep frozen-version code paths independent of it;
- freezing it requires a changelog entry that names the final vector set and a status change in the specification.

Draft V2 shares no wire objects with V1. V1 `ContactBundle`, `DropRef`, `MessageEnvelope`, and `DecryptedPayload` keep their frozen meaning; V2 defines `DropCapability`, a V2 `ContactBundle`, `ReceiveProfile`, a V2 payload, and a V2 envelope. A server that stores both validates each by its own `v` and never reinterprets one as the other.

## Changes requiring a new integer wire version

A new version is required for any incompatible change, including:

- adding, removing, renaming, relocating, or changing the type or meaning of a required wire field;
- changing key types, KDF inputs, AEAD parameters, associated data, signature transcript, or signature requirements;
- changing identifier or URL rules so previously conforming messages change validity;
- changing server write/read semantics in a way clients must detect;
- assigning protocol meaning to an unknown field that V1 consumers ignore.

The one-time recipient key, encrypted sender identity, and metadata-private public envelope from issue #1 are incompatible with V1; they are carried by draft V2, not by any reinterpretation of `v: 1`.

The optional `?wait=` long-poll query (V2 §8.1) is a server extension, not a wire change: a server that ignores it still answers correctly, and V1 clients never send it.

## Optional fields

An optional field is compatible only when the frozen specification defines it, old consumers can safely ignore it, and it does not alter required security interpretation. V1's `signature` is the only defined optional envelope field. Unknown V1 fields are ignored and unauthenticated; they MUST NOT carry protocol semantics.

## Consumer behavior

Consumers MUST reject unsupported `v` values rather than guessing. Implementations MAY support multiple versions, but parsing, validation, crypto, and state transitions must be selected explicitly by version. Downgrade must never happen silently.

Contact-bundle and envelope versions are explicit wire values. Local storage migrations must not be inferred from them.

## Test-vector policy

Every frozen version has normative vectors covering valid objects, exact cryptographic bytes, and invalid cases. A wire-affecting proposal must update or add vectors in the same change. Existing frozen vectors are immutable except to correct a demonstrable vector-generation error; such a correction requires a changelog entry and compatibility analysis.

## Deprecation and removal

Support may be deprecated in documentation at any time. Removing support from the reference implementation requires release notes, a migration path when local state is affected, and an explicit statement of the last supported wire version. Servers should remain version-agnostic only where their validation and storage rules safely allow it.
