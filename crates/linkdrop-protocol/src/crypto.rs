use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    decode_base64url, encode_base64url,
    encoding::{parse_tagged_base64, tagged_base64},
    error::{ProtocolError, Result},
    model::{DecryptedPayload, MessageEnvelope, SignatureState},
    state::IdentityFile,
};

const HKDF_INFO: &[u8] = b"linkdrop-v1-message";

pub fn generate_drop_id() -> String {
    random_base64url(32)
}

pub fn generate_message_id() -> String {
    random_base64url(16)
}

pub fn generate_contact_id() -> String {
    random_base64url(12)
}

pub fn now_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedEnvelope {
    pub payload: DecryptedPayload,
    pub signature_state: SignatureState,
}

pub fn encrypt_payload_for_contact(
    identity: &IdentityFile,
    recipient_prekey: &str,
    payload: &DecryptedPayload,
    sign_envelope: bool,
) -> Result<MessageEnvelope> {
    payload.validate(true)?;

    let recipient_public = x25519_public_key(recipient_prekey)?;
    let mut rng = OsRng;
    let ephemeral_secret = StaticSecret::random_from_rng(rng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
    let key = derive_message_key(shared_secret.as_bytes())?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| ProtocolError::Crypto("failed to construct cipher"))?;
    let mut nonce_bytes = [0_u8; 12];
    rng.fill_bytes(&mut nonce_bytes);

    let plaintext = serde_json::to_vec(payload)?;
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|_| ProtocolError::Crypto("message encryption failed"))?;

    Ok(MessageEnvelope {
        v: 1,
        msg_id: generate_message_id(),
        created_at: now_timestamp(),
        sender_identity_key: identity.tagged_identity_public_key(),
        sender_ephemeral_key: tagged_base64("x25519", ephemeral_public.as_bytes()),
        ciphertext: encode_base64url(&ciphertext),
        nonce: encode_base64url(&nonce_bytes),
        signature: None,
    })
    .and_then(|mut envelope| {
        if sign_envelope {
            envelope.signature = Some(sign_envelope_bytes(&identity.signing_key()?, &envelope)?);
        }
        Ok(envelope)
    })
}

pub fn decrypt_envelope(
    identity: &IdentityFile,
    envelope: &MessageEnvelope,
) -> Result<OpenedEnvelope> {
    envelope.validate(true)?;
    let signature_state = verify_optional_signature(envelope)?;

    let sender_ephemeral = x25519_public_key(&envelope.sender_ephemeral_key)?;
    let prekey_secret = identity.prekey_secret_key()?;
    let shared_secret = prekey_secret.diffie_hellman(&sender_ephemeral);
    let key = derive_message_key(shared_secret.as_bytes())?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| ProtocolError::Crypto("failed to construct cipher"))?;

    let nonce = decode_base64url(&envelope.nonce)?;
    let ciphertext = decode_base64url(&envelope.ciphertext)?;
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| ProtocolError::Crypto("message decryption failed"))?;
    let payload: DecryptedPayload = serde_json::from_slice(&plaintext)?;
    payload.validate(true)?;
    Ok(OpenedEnvelope {
        payload,
        signature_state,
    })
}

pub fn signing_key_from_base64(raw: &str) -> Result<SigningKey> {
    let bytes = decode_base64url(raw)?;
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        ProtocolError::Validation("ed25519 secret key must be 32 bytes".to_string())
    })?;
    Ok(SigningKey::from_bytes(&raw))
}

pub fn verifying_key_from_tagged_base64(tagged: &str) -> Result<VerifyingKey> {
    let bytes = parse_tagged_base64(tagged, "ed25519")?;
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        ProtocolError::Validation("ed25519 public key must be 32 bytes".to_string())
    })?;
    VerifyingKey::from_bytes(&raw)
        .map_err(|_| ProtocolError::Validation("invalid ed25519 public key".to_string()))
}

pub fn x25519_public_key(tagged: &str) -> Result<PublicKey> {
    let bytes = parse_tagged_base64(tagged, "x25519")?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ProtocolError::Validation("x25519 key must be 32 bytes".to_string()))?;
    Ok(PublicKey::from(raw))
}

pub fn x25519_secret_key(raw: &str) -> Result<StaticSecret> {
    let bytes = decode_base64url(raw)?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ProtocolError::Validation("x25519 secret key must be 32 bytes".to_string()))?;
    Ok(StaticSecret::from(raw))
}

fn sign_envelope_bytes(signing_key: &SigningKey, envelope: &MessageEnvelope) -> Result<String> {
    let unsigned = unsigned_envelope_bytes(envelope)?;
    let signature = signing_key.sign(&unsigned);
    Ok(encode_base64url(&signature.to_bytes()))
}

fn verify_optional_signature(envelope: &MessageEnvelope) -> Result<SignatureState> {
    let Some(signature) = &envelope.signature else {
        return Ok(SignatureState::Unsigned);
    };

    let verifying_key = verifying_key_from_tagged_base64(&envelope.sender_identity_key)?;
    let signature_bytes = decode_base64url(signature)?;
    let raw: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| ProtocolError::Validation("signature must be 64 bytes".to_string()))?;
    let signature = Signature::from_bytes(&raw);
    let unsigned = unsigned_envelope_bytes(envelope)?;
    verifying_key.verify(&unsigned, &signature).map_err(|_| {
        ProtocolError::Signature("envelope signature verification failed".to_string())
    })?;
    Ok(SignatureState::Verified)
}

fn unsigned_envelope_bytes(envelope: &MessageEnvelope) -> Result<Vec<u8>> {
    let mut unsigned = envelope.clone();
    unsigned.signature = None;
    serde_json::to_vec(&unsigned).map_err(ProtocolError::from)
}

fn derive_message_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0_u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|_| ProtocolError::Crypto("HKDF expansion failed"))?;
    Ok(key)
}

fn random_base64url(bytes_len: usize) -> String {
    let mut bytes = vec![0_u8; bytes_len];
    OsRng.fill_bytes(&mut bytes);
    encode_base64url(&bytes)
}
