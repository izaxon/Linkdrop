//! V2 sealing, opening, and the signature transcript (spec §5).

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand::{RngCore, rngs::OsRng};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    crypto::{verifying_key_from_tagged_base64, x25519_public_key},
    decode_base64url, encode_base64url,
    encoding::{parse_tagged_base64, tagged_base64},
    error::{ProtocolError, Result},
    v2::{
        chain::derive_message_key,
        model::{DropCapability, Envelope, Payload, PayloadContent, ReceiveProfile, WIRE_VERSION},
    },
};

pub const TRANSCRIPT_DOMAIN: &[u8] = b"linkdrop-v2-signature\0";

/// Result of sealing: the public envelope plus the shared secret the sender may need for
/// generation-0 chain derivation after a capability message.
#[derive(Clone, Debug)]
pub struct Sealed {
    pub envelope: Envelope,
    pub shared_secret: [u8; 32],
    pub plaintext: Vec<u8>,
}

/// Result of opening: the verified payload plus the shared secret.
#[derive(Clone, Debug)]
pub struct Opened {
    pub payload: Payload,
    pub shared_secret: [u8; 32],
}

/// Seal `content` for the drop `drop_id`, encrypting to `receive_key`, with fresh randomness.
pub fn seal(
    signing_key: &SigningKey,
    receive_key: &str,
    drop_id: &str,
    content: &PayloadContent,
) -> Result<Sealed> {
    let mut rng = OsRng;
    let ephemeral_secret = StaticSecret::random_from_rng(rng);
    let mut nonce = [0_u8; 12];
    rng.fill_bytes(&mut nonce);
    seal_with(
        signing_key,
        receive_key,
        drop_id,
        content,
        ephemeral_secret,
        nonce,
    )
}

/// Deterministic sealing used by the normative vectors. Never reuse a nonce or ephemeral
/// secret outside tests.
pub fn seal_with(
    signing_key: &SigningKey,
    receive_key: &str,
    drop_id: &str,
    content: &PayloadContent,
    ephemeral_secret: StaticSecret,
    nonce: [u8; 12],
) -> Result<Sealed> {
    content.validate(true)?;
    let receive_public = x25519_public_key(receive_key)?;
    let drop_id_bytes = decode_base64url(drop_id)?;
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&receive_public);
    if !shared.was_contributory() {
        return Err(ProtocolError::Crypto("x25519 shared secret is all zero"));
    }
    let shared_secret = *shared.as_bytes();

    let identity_bytes = signing_key.verifying_key().to_bytes();
    let transcript = signature_transcript(
        &drop_id_bytes,
        ephemeral_public.as_bytes(),
        receive_public.as_bytes(),
        content,
        &identity_bytes,
    );
    let payload = Payload {
        content: content.clone(),
        sender_identity_key: tagged_base64("ed25519", &identity_bytes),
        signature: encode_base64url(&signing_key.sign(&transcript).to_bytes()),
    };
    let plaintext = serde_json::to_vec(&payload)?;

    let key = derive_message_key(&shared_secret, &drop_id_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| ProtocolError::Crypto("failed to construct cipher"))?;
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| ProtocolError::Crypto("message encryption failed"))?;

    Ok(Sealed {
        envelope: Envelope {
            v: WIRE_VERSION,
            sender_ephemeral_key: tagged_base64("x25519", ephemeral_public.as_bytes()),
            nonce: encode_base64url(&nonce),
            ciphertext: encode_base64url(&ciphertext),
        },
        shared_secret,
        plaintext,
    })
}

/// Open an envelope fetched from `drop_id` with the receive secret for that drop or generation.
pub fn open(receive_secret: &StaticSecret, drop_id: &str, envelope: &Envelope) -> Result<Opened> {
    envelope.validate()?;
    let drop_id_bytes = decode_base64url(drop_id)?;
    let ephemeral_public = x25519_public_key(&envelope.sender_ephemeral_key)?;
    let shared = receive_secret.diffie_hellman(&ephemeral_public);
    if !shared.was_contributory() {
        return Err(ProtocolError::Crypto("x25519 shared secret is all zero"));
    }
    let shared_secret = *shared.as_bytes();

    let key = derive_message_key(&shared_secret, &drop_id_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| ProtocolError::Crypto("failed to construct cipher"))?;
    let nonce = decode_base64url(&envelope.nonce)?;
    let ciphertext = decode_base64url(&envelope.ciphertext)?;
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| ProtocolError::Crypto("message decryption failed"))?;

    let payload: Payload = serde_json::from_slice(&plaintext)?;
    payload.validate(true)?;
    verify_payload_signature(
        &drop_id_bytes,
        ephemeral_public.as_bytes(),
        PublicKey::from(receive_secret).as_bytes(),
        &payload,
    )?;
    Ok(Opened {
        payload,
        shared_secret,
    })
}

/// Verify the mandatory signature of an already-decrypted payload.
pub fn verify_payload_signature(
    drop_id_bytes: &[u8],
    ephemeral_public: &[u8; 32],
    receive_public: &[u8; 32],
    payload: &Payload,
) -> Result<()> {
    let identity_bytes = parse_tagged_base64(&payload.sender_identity_key, "ed25519")?;
    let transcript = signature_transcript(
        drop_id_bytes,
        ephemeral_public,
        receive_public,
        &payload.content,
        &identity_bytes,
    );
    let verifying_key = verifying_key_from_tagged_base64(&payload.sender_identity_key)?;
    let raw: [u8; 64] = decode_base64url(&payload.signature)?
        .try_into()
        .map_err(|_| ProtocolError::Validation("signature must be 64 bytes".to_string()))?;
    verifying_key
        .verify(&transcript, &Signature::from_bytes(&raw))
        .map_err(|_| ProtocolError::Signature("payload signature verification failed".to_string()))
}

/// The canonical binary transcript from spec §5.4.
pub fn signature_transcript(
    drop_id_bytes: &[u8],
    ephemeral_public: &[u8; 32],
    receive_public: &[u8; 32],
    content: &PayloadContent,
    identity_bytes: &[u8],
) -> Vec<u8> {
    let mut t = Transcript::default();
    t.bytes.extend_from_slice(TRANSCRIPT_DOMAIN);
    t.item(drop_id_bytes);
    t.item(ephemeral_public);
    t.item(receive_public);
    t.item(content.message_type.as_str().as_bytes());
    t.item(&decode_base64url(&content.msg_id).unwrap_or_default());
    t.int(content.created_at as i128);
    t.int(content.seq as i128);
    t.opt(content.text.as_deref(), |t, text| t.item(text.as_bytes()));
    t.opt(content.ack, |t, ack| t.int(ack as i128));
    t.list(
        content.missing.as_deref().unwrap_or_default(),
        |t, value| t.int(*value as i128),
    );
    t.opt(content.resend_of, |t, value| t.int(value as i128));
    t.opt(content.receive.as_ref(), |t, profile| t.profile(profile));
    t.opt(content.rescue.as_ref(), |t, capability| {
        t.capability(capability)
    });
    t.item(identity_bytes);
    t.bytes
}

#[derive(Default)]
struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    fn item(&mut self, value: &[u8]) {
        self.bytes
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.bytes.extend_from_slice(value);
    }

    fn int(&mut self, value: i128) {
        self.item(value.to_string().as_bytes());
    }

    fn opt<T>(&mut self, value: Option<T>, write: impl FnOnce(&mut Self, T)) {
        match value {
            None => self.bytes.push(0x00),
            Some(value) => {
                self.bytes.push(0x01);
                write(self, value);
            }
        }
    }

    fn list<T>(&mut self, values: &[T], write: impl Fn(&mut Self, &T)) {
        self.bytes
            .extend_from_slice(&(values.len() as u32).to_be_bytes());
        for value in values {
            write(self, value);
        }
    }

    fn profile(&mut self, profile: &ReceiveProfile) {
        self.int(profile.generation as i128);
        self.item(&decode_base64url(&profile.chain_key).unwrap_or_default());
        self.item(&parse_tagged_base64(&profile.receive_key, "x25519").unwrap_or_default());
        self.list(&profile.servers, |t, server| t.item(server.as_bytes()));
    }

    fn capability(&mut self, capability: &DropCapability) {
        self.item(capability.server.as_bytes());
        self.item(&decode_base64url(&capability.drop_id).unwrap_or_default());
        self.item(&parse_tagged_base64(&capability.recipient_key, "x25519").unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::model::MessageType;

    fn content() -> PayloadContent {
        PayloadContent {
            message_type: MessageType::Text,
            msg_id: encode_base64url(&[7_u8; 16]),
            created_at: 1_777_000_100,
            seq: 0,
            text: Some("hello".to_string()),
            ack: None,
            missing: None,
            resend_of: None,
            receive: None,
            rescue: None,
        }
    }

    #[test]
    fn seal_and_open_round_trip_and_bind_drop_id() {
        let signing_key = SigningKey::from_bytes(&[3_u8; 32]);
        let receive_secret = StaticSecret::from([5_u8; 32]);
        let receive_key = tagged_base64("x25519", PublicKey::from(&receive_secret).as_bytes());
        let drop_id = encode_base64url(&[9_u8; 32]);

        let sealed = seal(&signing_key, &receive_key, &drop_id, &content()).unwrap();
        let opened = open(&receive_secret, &drop_id, &sealed.envelope).unwrap();
        assert_eq!(opened.payload.content, content());
        assert_eq!(opened.shared_secret, sealed.shared_secret);

        let other_drop = encode_base64url(&[10_u8; 32]);
        assert!(open(&receive_secret, &other_drop, &sealed.envelope).is_err());
    }

    #[test]
    fn tampered_signature_inside_ciphertext_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[3_u8; 32]);
        let receive_secret = StaticSecret::from([5_u8; 32]);
        let receive_key = tagged_base64("x25519", PublicKey::from(&receive_secret).as_bytes());
        let drop_id = encode_base64url(&[9_u8; 32]);
        let sealed = seal(&signing_key, &receive_key, &drop_id, &content()).unwrap();

        let mut payload: Payload = serde_json::from_slice(&sealed.plaintext).unwrap();
        let mut signature = decode_base64url(&payload.signature).unwrap();
        signature[0] ^= 1;
        payload.signature = encode_base64url(&signature);
        let drop_id_bytes = decode_base64url(&drop_id).unwrap();
        let ephemeral = x25519_public_key(&sealed.envelope.sender_ephemeral_key).unwrap();
        assert!(
            verify_payload_signature(
                &drop_id_bytes,
                ephemeral.as_bytes(),
                PublicKey::from(&receive_secret).as_bytes(),
                &payload
            )
            .is_err()
        );
    }
}
