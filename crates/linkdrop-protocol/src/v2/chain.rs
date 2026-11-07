//! Derived drop chains (spec §4) and the V2 key schedule (spec §5.1–5.2).

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{
    decode_base64url, encode_base64url,
    error::{ProtocolError, Result},
    model::DropRef,
    v2::model::ReceiveProfile,
};

pub const DROP_ID_INFO: &[u8] = b"linkdrop-v2-drop-id";
pub const CHAIN_KEY_INFO: &[u8] = b"linkdrop-v2-chain-key";
pub const MESSAGE_KEY_INFO: &[u8] = b"linkdrop-v2-message-key";

/// `drop_id(P, n)` from spec §4.2: HKDF over the chain key with the sequence number in `info`.
pub fn derive_drop_id(chain_key: &[u8; 32], seq: u64) -> String {
    let mut info = Vec::with_capacity(DROP_ID_INFO.len() + 8);
    info.extend_from_slice(DROP_ID_INFO);
    info.extend_from_slice(&seq.to_be_bytes());
    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut out = [0_u8; 32];
    hk.expand(&info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    encode_base64url(&out)
}

/// `server(P, n)` from spec §4.2.
pub fn select_server(servers: &[String], seq: u64) -> Result<&str> {
    if servers.is_empty() {
        return Err(ProtocolError::Validation(
            "receive profile must list at least one server".to_string(),
        ));
    }
    let index = (seq % servers.len() as u64) as usize;
    Ok(servers[index].as_str())
}

/// The drop a message with sequence number `seq` is written to under `profile`.
pub fn chain_drop(profile: &ReceiveProfile, seq: u64) -> Result<DropRef> {
    let chain_key = chain_key_bytes(&profile.chain_key)?;
    Ok(DropRef {
        server: select_server(&profile.servers, seq)?.to_string(),
        drop_id: derive_drop_id(&chain_key, seq),
    })
}

/// Generation-0 chain key of a direction established by a capability message (spec §4.1).
pub fn derive_chain_key(shared_secret: &[u8; 32], drop_id_bytes: &[u8]) -> [u8; 32] {
    hkdf_32(shared_secret, drop_id_bytes, CHAIN_KEY_INFO)
}

/// Per-message AEAD key (spec §5.2).
pub fn derive_message_key(shared_secret: &[u8; 32], drop_id_bytes: &[u8]) -> [u8; 32] {
    hkdf_32(shared_secret, drop_id_bytes, MESSAGE_KEY_INFO)
}

pub fn chain_key_bytes(encoded: &str) -> Result<[u8; 32]> {
    decode_base64url(encoded)?.try_into().map_err(|_| {
        ProtocolError::Validation("chain_key must encode exactly 32 bytes".to_string())
    })
}

fn hkdf_32(ikm: &[u8; 32], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0_u8; 32];
    hk.expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_ids_differ_per_sequence_and_chain() {
        let key_a = [1_u8; 32];
        let key_b = [2_u8; 32];
        assert_ne!(derive_drop_id(&key_a, 0), derive_drop_id(&key_a, 1));
        assert_ne!(derive_drop_id(&key_a, 0), derive_drop_id(&key_b, 0));
        assert_eq!(derive_drop_id(&key_a, 7), derive_drop_id(&key_a, 7));
        assert_eq!(
            decode_base64url(&derive_drop_id(&key_a, 0)).unwrap().len(),
            32
        );
    }

    #[test]
    fn servers_rotate_by_sequence() {
        let servers = vec![
            "https://a.example".to_string(),
            "https://b.example".to_string(),
        ];
        assert_eq!(select_server(&servers, 0).unwrap(), "https://a.example");
        assert_eq!(select_server(&servers, 1).unwrap(), "https://b.example");
        assert_eq!(select_server(&servers, 2).unwrap(), "https://a.example");
        assert!(select_server(&[], 0).is_err());
    }
}
