use serde::{Deserialize, Serialize};

use crate::{
    decode_base64url,
    encoding::{parse_tagged_base64, validate_server_url},
    error::{ProtocolError, Result},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DropRef {
    pub server: String,
    pub drop_id: String,
}

impl DropRef {
    pub fn validate(&self, allow_http_local: bool) -> Result<()> {
        validate_server_url(&self.server, allow_http_local)?;
        let drop_id = decode_base64url(&self.drop_id)?;
        if drop_id.len() < 16 {
            return Err(ProtocolError::Validation(
                "drop_id must encode at least 16 random bytes".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactBundle {
    pub v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub identity_key: String,
    pub prekey: String,
    pub initial_drops: Vec<DropRef>,
}

impl ContactBundle {
    pub fn validate(&self, allow_http_local: bool) -> Result<()> {
        if self.v != 1 {
            return Err(ProtocolError::Validation(
                "contact bundle version must be 1".to_string(),
            ));
        }
        validate_ed25519_key(&self.identity_key)?;
        validate_x25519_key(&self.prekey)?;
        if self.initial_drops.is_empty() {
            return Err(ProtocolError::Validation(
                "contact bundle must contain at least one initial drop".to_string(),
            ));
        }
        for drop_ref in &self.initial_drops {
            drop_ref.validate(allow_http_local)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub v: u8,
    pub msg_id: String,
    pub created_at: i64,
    pub sender_identity_key: String,
    pub sender_ephemeral_key: String,
    pub ciphertext: String,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl MessageEnvelope {
    pub fn validate(&self, _allow_http_local: bool) -> Result<()> {
        if self.v != 1 {
            return Err(ProtocolError::Validation(
                "message envelope version must be 1".to_string(),
            ));
        }
        if decode_base64url(&self.msg_id)?.is_empty() {
            return Err(ProtocolError::Validation(
                "msg_id must be non-empty base64url".to_string(),
            ));
        }
        validate_ed25519_key(&self.sender_identity_key)?;
        validate_x25519_key(&self.sender_ephemeral_key)?;
        if decode_base64url(&self.ciphertext)?.is_empty() {
            return Err(ProtocolError::Validation(
                "ciphertext must be non-empty".to_string(),
            ));
        }
        if decode_base64url(&self.nonce)?.len() != 12 {
            return Err(ProtocolError::Validation(
                "nonce must be 12 bytes for ChaCha20-Poly1305".to_string(),
            ));
        }
        if let Some(signature) = &self.signature {
            if decode_base64url(signature)?.len() != 64 {
                return Err(ProtocolError::Validation(
                    "signature must be 64 bytes when present".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptedPayload {
    pub text: String,
    pub reply_drop: DropRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_msg_id: Option<String>,
}

impl DecryptedPayload {
    pub fn validate(&self, allow_http_local: bool) -> Result<()> {
        if self.text.is_empty() {
            return Err(ProtocolError::Validation(
                "payload text must be non-empty".to_string(),
            ));
        }
        self.reply_drop.validate(allow_http_local)?;
        if let Some(prev) = &self.prev_msg_id {
            if decode_base64url(prev)?.is_empty() {
                return Err(ProtocolError::Validation(
                    "prev_msg_id must be non-empty base64url".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureState {
    #[default]
    Unsigned,
    Signed,
    Verified,
    Invalid,
}

fn validate_ed25519_key(value: &str) -> Result<()> {
    let bytes = parse_tagged_base64(value, "ed25519")?;
    if bytes.len() != 32 {
        return Err(ProtocolError::Validation(
            "ed25519 key must contain 32 public-key bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_x25519_key(value: &str) -> Result<()> {
    let bytes = parse_tagged_base64(value, "x25519")?;
    if bytes.len() != 32 {
        return Err(ProtocolError::Validation(
            "x25519 key must contain 32 bytes".to_string(),
        ));
    }
    Ok(())
}
