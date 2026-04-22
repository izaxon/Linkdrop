use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    crypto::{signing_key_from_base64, x25519_secret_key},
    encoding::{decode_base64url, encode_base64url, tagged_base64},
    error::{ProtocolError, Result},
    model::{DropRef, SignatureState},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityFile {
    pub v: u8,
    pub display_name: String,
    pub identity_secret_key: String,
    pub identity_public_key: String,
    pub prekey_secret_key: String,
    pub prekey_public_key: String,
}

impl IdentityFile {
    pub fn generate(display_name: impl Into<String>) -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verify_key = signing_key.verifying_key();
        let prekey_secret = StaticSecret::random_from_rng(rng);
        let prekey_public = PublicKey::from(&prekey_secret);

        Self {
            v: 1,
            display_name: display_name.into(),
            identity_secret_key: encode_base64url(&signing_key.to_bytes()),
            identity_public_key: encode_base64url(verify_key.as_bytes()),
            prekey_secret_key: encode_base64url(&prekey_secret.to_bytes()),
            prekey_public_key: encode_base64url(prekey_public.as_bytes()),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.v != 1 {
            return Err(ProtocolError::Validation(
                "identity file version must be 1".to_string(),
            ));
        }
        if self.display_name.trim().is_empty() {
            return Err(ProtocolError::Validation(
                "display name must not be empty".to_string(),
            ));
        }
        let identity_secret = decode_base64url(&self.identity_secret_key)?;
        let identity_public = decode_base64url(&self.identity_public_key)?;
        let prekey_secret = decode_base64url(&self.prekey_secret_key)?;
        let prekey_public = decode_base64url(&self.prekey_public_key)?;

        if identity_secret.len() != 32 || identity_public.len() != 32 {
            return Err(ProtocolError::Validation(
                "identity keys must contain 32 bytes".to_string(),
            ));
        }
        if prekey_secret.len() != 32 || prekey_public.len() != 32 {
            return Err(ProtocolError::Validation(
                "prekey keys must contain 32 bytes".to_string(),
            ));
        }
        Ok(())
    }

    pub fn tagged_identity_public_key(&self) -> String {
        tagged_base64(
            "ed25519",
            &decode_base64url(&self.identity_public_key).unwrap_or_default(),
        )
    }

    pub fn tagged_prekey_public_key(&self) -> String {
        tagged_base64(
            "x25519",
            &decode_base64url(&self.prekey_public_key).unwrap_or_default(),
        )
    }

    pub fn signing_key(&self) -> Result<SigningKey> {
        signing_key_from_base64(&self.identity_secret_key)
    }

    pub fn prekey_secret_key(&self) -> Result<StaticSecret> {
        x25519_secret_key(&self.prekey_secret_key)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactsFile {
    pub v: u8,
    #[serde(default)]
    pub contacts: Vec<ContactRecord>,
}

impl Default for ContactsFile {
    fn default() -> Self {
        Self {
            v: 1,
            contacts: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactRecord {
    pub contact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub identity_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prekey: Option<String>,
    #[serde(default)]
    pub initial_drops: Vec<DropRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_outgoing_drop: Option<DropRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientStateFile {
    pub v: u8,
    #[serde(default)]
    pub watched_drops: Vec<WatchedDrop>,
    #[serde(default)]
    pub preferred_servers: Vec<String>,
    #[serde(default)]
    pub next_server_index: usize,
}

impl Default for ClientStateFile {
    fn default() -> Self {
        Self {
            v: 1,
            watched_drops: Vec::new(),
            preferred_servers: Vec::new(),
            next_server_index: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchedDrop {
    pub drop: DropRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessagesFile {
    pub v: u8,
    #[serde(default)]
    pub messages: Vec<MessageRecord>,
}

impl Default for MessagesFile {
    fn default() -> Self {
        Self {
            v: 1,
            messages: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageRecord {
    pub msg_id: String,
    pub contact_id: String,
    pub direction: MessageDirection,
    pub created_at: i64,
    pub text: String,
    pub status: MessageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_drop: Option<DropRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_drop_generated: Option<DropRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_from_drop: Option<DropRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_msg_id: Option<String>,
    #[serde(default)]
    pub signature_state: SignatureState,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageStatus {
    Pending,
    Sent,
    Failed,
    Received,
    Invalid,
}
