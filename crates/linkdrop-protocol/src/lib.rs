mod crypto;
mod encoding;
mod error;
mod model;
mod state;

pub use crypto::{
    OpenedEnvelope, decrypt_envelope, encrypt_payload_for_contact, generate_contact_id,
    generate_drop_id, generate_message_id, now_timestamp,
};
pub use encoding::{
    decode_base64url, encode_base64url, parse_tagged_base64, tagged_base64, validate_server_url,
};
pub use error::{ProtocolError, Result};
pub use model::{ContactBundle, DecryptedPayload, DropRef, MessageEnvelope, SignatureState};
pub use state::{
    ClientStateFile, ContactRecord, ContactsFile, IdentityFile, MessageDirection, MessageRecord,
    MessageStatus, MessagesFile, WatchedDrop,
};
