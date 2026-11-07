//! V2 wire objects (draft). See `linkdrop-v2-spec.md` §3.

use serde::{Deserialize, Serialize};

use crate::{
    decode_base64url,
    encoding::{parse_tagged_base64, validate_server_url},
    error::{ProtocolError, Result},
};

/// Wire version emitted and accepted by this module.
pub const WIRE_VERSION: u8 = 2;

/// Largest integer V2 allows in `seq`, `generation`, `ack`, and `missing`.
pub const MAX_COUNTER: u64 = (1 << 53) - 1;

/// A one-time receive capability (spec §3.1).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DropCapability {
    pub server: String,
    pub drop_id: String,
    pub recipient_key: String,
}

impl DropCapability {
    pub fn validate(&self, allow_http_local: bool) -> Result<()> {
        validate_server_url(&self.server, allow_http_local)?;
        if decode_base64url(&self.drop_id)?.len() < 16 {
            return Err(ProtocolError::Validation(
                "drop_id must encode at least 16 random bytes".to_string(),
            ));
        }
        validate_x25519_key(&self.recipient_key)
    }
}

/// A V2 contact bundle (spec §3.2).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactBundle {
    pub v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub identity_key: String,
    pub initial: Vec<DropCapability>,
}

impl ContactBundle {
    pub fn validate(&self, allow_http_local: bool) -> Result<()> {
        if self.v != WIRE_VERSION {
            return Err(ProtocolError::Validation(
                "contact bundle version must be 2".to_string(),
            ));
        }
        validate_ed25519_key(&self.identity_key)?;
        if self.initial.is_empty() {
            return Err(ProtocolError::Validation(
                "contact bundle must contain at least one initial capability".to_string(),
            ));
        }
        for (index, capability) in self.initial.iter().enumerate() {
            capability.validate(allow_http_local)?;
            if self.initial[..index]
                .iter()
                .any(|other| other.drop_id == capability.drop_id)
            {
                return Err(ProtocolError::Validation(
                    "initial capabilities must have distinct drop_id values".to_string(),
                ));
            }
            if self.initial[..index]
                .iter()
                .any(|other| other.recipient_key == capability.recipient_key)
            {
                return Err(ProtocolError::Validation(
                    "initial capabilities must have distinct recipient keys".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// How the owner wants to receive the next generation of one direction (spec §3.3).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiveProfile {
    #[serde(rename = "gen")]
    pub generation: u64,
    pub chain_key: String,
    pub receive_key: String,
    pub servers: Vec<String>,
}

impl ReceiveProfile {
    pub fn validate(&self, allow_http_local: bool) -> Result<()> {
        validate_counter(self.generation, "gen")?;
        if decode_base64url(&self.chain_key)?.len() != 32 {
            return Err(ProtocolError::Validation(
                "chain_key must encode exactly 32 bytes".to_string(),
            ));
        }
        validate_x25519_key(&self.receive_key)?;
        if self.servers.is_empty() {
            return Err(ProtocolError::Validation(
                "receive profile must list at least one server".to_string(),
            ));
        }
        for (index, server) in self.servers.iter().enumerate() {
            validate_server_url(server, allow_http_local)?;
            if self.servers[..index].contains(server) {
                return Err(ProtocolError::Validation(
                    "receive profile servers must be distinct".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Text,
    Control,
}

impl MessageType {
    pub fn as_str(self) -> &'static str {
        match self {
            MessageType::Text => "text",
            MessageType::Control => "control",
        }
    }
}

/// Everything in the plaintext except the sender's identity and signature (spec §3.4).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadContent {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    pub msg_id: String,
    pub created_at: i64,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resend_of: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive: Option<ReceiveProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rescue: Option<DropCapability>,
}

impl PayloadContent {
    pub fn validate(&self, allow_http_local: bool) -> Result<()> {
        if decode_base64url(&self.msg_id)?.is_empty() {
            return Err(ProtocolError::Validation(
                "msg_id must be non-empty base64url".to_string(),
            ));
        }
        validate_counter(self.seq, "seq")?;
        match (self.message_type, &self.text) {
            (MessageType::Text, Some(text)) if !text.is_empty() => {}
            (MessageType::Text, _) => {
                return Err(ProtocolError::Validation(
                    "text messages must carry non-empty text".to_string(),
                ));
            }
            (MessageType::Control, None) => {}
            (MessageType::Control, Some(_)) => {
                return Err(ProtocolError::Validation(
                    "control messages must not carry text".to_string(),
                ));
            }
        }
        if let Some(ack) = self.ack {
            validate_counter(ack, "ack")?;
        }
        if let Some(missing) = &self.missing {
            let Some(ack) = self.ack else {
                return Err(ProtocolError::Validation(
                    "missing requires ack".to_string(),
                ));
            };
            if missing.is_empty() {
                return Err(ProtocolError::Validation(
                    "missing must not be empty when present".to_string(),
                ));
            }
            for (index, value) in missing.iter().enumerate() {
                if *value >= ack {
                    return Err(ProtocolError::Validation(
                        "missing values must be below ack".to_string(),
                    ));
                }
                if index > 0 && missing[index - 1] >= *value {
                    return Err(ProtocolError::Validation(
                        "missing must be strictly increasing".to_string(),
                    ));
                }
            }
        }
        if let Some(resend_of) = self.resend_of {
            validate_counter(resend_of, "resend_of")?;
            if resend_of >= self.seq {
                return Err(ProtocolError::Validation(
                    "resend_of must be below seq".to_string(),
                ));
            }
        }
        if let Some(receive) = &self.receive {
            receive.validate(allow_http_local)?;
        }
        if let Some(rescue) = &self.rescue {
            rescue.validate(allow_http_local)?;
        }
        Ok(())
    }
}

/// The complete AEAD plaintext (spec §3.4).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Payload {
    #[serde(flatten)]
    pub content: PayloadContent,
    pub sender_identity_key: String,
    pub signature: String,
}

impl Payload {
    pub fn validate(&self, allow_http_local: bool) -> Result<()> {
        self.content.validate(allow_http_local)?;
        validate_ed25519_key(&self.sender_identity_key)?;
        if decode_base64url(&self.signature)?.len() != 64 {
            return Err(ProtocolError::Validation(
                "signature must be 64 bytes".to_string(),
            ));
        }
        Ok(())
    }
}

/// The public object uploaded to a server (spec §3.5).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub v: u8,
    pub sender_ephemeral_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl Envelope {
    pub fn validate(&self) -> Result<()> {
        if self.v != WIRE_VERSION {
            return Err(ProtocolError::Validation(
                "message envelope version must be 2".to_string(),
            ));
        }
        validate_x25519_key(&self.sender_ephemeral_key)?;
        if decode_base64url(&self.nonce)?.len() != 12 {
            return Err(ProtocolError::Validation(
                "nonce must be 12 bytes for ChaCha20-Poly1305".to_string(),
            ));
        }
        if decode_base64url(&self.ciphertext)?.len() <= 16 {
            return Err(ProtocolError::Validation(
                "ciphertext must contain at least one byte beyond the tag".to_string(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_counter(value: u64, name: &str) -> Result<()> {
    if value > MAX_COUNTER {
        return Err(ProtocolError::Validation(format!(
            "{name} must be below 2^53"
        )));
    }
    Ok(())
}

pub(crate) fn validate_ed25519_key(value: &str) -> Result<()> {
    if parse_tagged_base64(value, "ed25519")?.len() != 32 {
        return Err(ProtocolError::Validation(
            "ed25519 key must contain 32 public-key bytes".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_x25519_key(value: &str) -> Result<()> {
    if parse_tagged_base64(value, "x25519")?.len() != 32 {
        return Err(ProtocolError::Validation(
            "x25519 key must contain 32 bytes".to_string(),
        ));
    }
    Ok(())
}
