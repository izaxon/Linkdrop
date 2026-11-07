//! Draft wire version 2: asynchronous mailbox over derived drop chains.
//!
//! Everything here is selected explicitly by `v: 2`. Nothing changes the frozen V1 types in
//! the crate root. See `linkdrop-v2-spec.md`.

pub mod chain;
pub mod crypto;
pub mod model;
pub mod session;

pub use chain::{
    chain_drop, chain_key_bytes, derive_chain_key, derive_drop_id, derive_message_key,
    select_server,
};
pub use crypto::{
    Opened, Sealed, open, seal, seal_with, signature_transcript, verify_payload_signature,
};
pub use model::{
    ContactBundle, DropCapability, Envelope, MAX_COUNTER, MessageType, Payload, PayloadContent,
    ReceiveProfile, WIRE_VERSION,
};
pub use session::{
    Conversation, DEFAULT_WINDOW, DropStatus, Incoming, MAX_RESENDS, OutboxEntry, Outgoing,
    OwnedCapability, OwnedGeneration, PollOutcome, RecvState, SendState, SendTarget, WatchTarget,
};
