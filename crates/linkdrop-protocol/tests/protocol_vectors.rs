use chacha20poly1305::{\n    ChaCha20Poly1305, KeyInit,\n    aead::{Aead, generic_array::GenericArray},\n};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use linkdrop_protocol::{
    ContactBundle, DecryptedPayload, IdentityFile, MessageEnvelope, SignatureState,
    decode_base64url, decrypt_envelope, parse_tagged_base64,
};
use serde_json::Value;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../test-vectors/v1/normative.json"))
        .expect("normative vector JSON must parse")
}

fn fixed_32(value: &str) -> [u8; 32] {
    decode_base64url(value)
        .expect("vector must be base64url")
        .try_into()
        .expect("vector must contain 32 bytes")
}

#[test]
fn valid_contact_bundle_and_payload_match_v1_models() {
    let vectors = vectors();
    let contact: ContactBundle =
        serde_json::from_value(vectors["contact_bundle"]["json"].clone()).unwrap();
    contact.validate(false).unwrap();

    let payload: DecryptedPayload = serde_json::from_value(
        vectors["encrypted_message"]["payload"]["json"].clone(),
    )
    .unwrap();
    payload.validate(false).unwrap();

    let serialized = serde_json::to_string(&payload).unwrap();
    assert_eq!(
        serialized,
        vectors["encrypted_message"]["payload"]["plaintext_utf8"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        linkdrop_protocol::encode_base64url(serialized.as_bytes()),
        vectors["encrypted_message"]["payload"]["plaintext_base64url"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn x25519_hkdf_and_chacha20poly1305_match_normative_bytes() {
    let vectors = vectors();
    let message = &vectors["encrypted_message"];

    let recipient_secret = StaticSecret::from(fixed_32(
        message["recipient_identity"]["prekey_secret_key"]
            .as_str()
            .unwrap(),
    ));
    let ephemeral_bytes = parse_tagged_base64(
        message["sender_ephemeral_public_key"].as_str().unwrap(),
        "x25519",
    )
    .unwrap();
    let ephemeral_public = PublicKey::from(
        <[u8; 32]>::try_from(ephemeral_bytes).expect("ephemeral public key must contain 32 bytes"),
    );
    let shared = recipient_secret.diffie_hellman(&ephemeral_public);
    let sender_secret = StaticSecret::from(fixed_32(
        message["sender_ephemeral_secret_key"].as_str().unwrap(),
    ));
    let recipient_public_bytes = parse_tagged_base64(
        vectors["contact_bundle"]["json"]["prekey"]
            .as_str()
            .unwrap(),
        "x25519",
    )
    .unwrap();
    let recipient_public = PublicKey::from(
        <[u8; 32]>::try_from(recipient_public_bytes)
            .expect("recipient public key must contain 32 bytes"),
    );
    assert_eq!(
        sender_secret.diffie_hellman(&recipient_public).as_bytes(),
        shared.as_bytes()
    );
    assert_eq!(
        linkdrop_protocol::encode_base64url(shared.as_bytes()),
        message["x25519_shared_secret"].as_str().unwrap()
    );

    let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0_u8; 32];
    hkdf.expand(
        message["hkdf"]["info_utf8"].as_str().unwrap().as_bytes(),
        &mut key,
    )
    .unwrap();
    assert_eq!(
        linkdrop_protocol::encode_base64url(&key),
        message["hkdf"]["message_key"].as_str().unwrap()
    );

    let nonce = decode_base64url(message["nonce"].as_str().unwrap()).unwrap();
    let plaintext = message["payload"]["plaintext_utf8"]
        .as_str()
        .unwrap()
        .as_bytes();
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&nonce), plaintext)
        .unwrap();
    assert_eq!(
        linkdrop_protocol::encode_base64url(&ciphertext),
        message["ciphertext"].as_str().unwrap()
    );
}

#[test]
fn signature_transcript_and_decryption_match_normative_bytes() {
    let vectors = vectors();
    let message = &vectors["encrypted_message"];
    let envelope: MessageEnvelope =
        serde_json::from_value(message["public_envelope"].clone()).unwrap();
    envelope.validate(false).unwrap();

    let mut unsigned = envelope.clone();
    unsigned.signature = None;
    let transcript = serde_json::to_vec(&unsigned).unwrap();
    assert_eq!(
        transcript,
        message["signature_transcript_utf8"]
            .as_str()
            .unwrap()
            .as_bytes()
    );

    let public_bytes =
        parse_tagged_base64(&envelope.sender_identity_key, "ed25519").unwrap();
    let verifying_key = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(public_bytes).expect("identity key must contain 32 bytes"),
    )
    .unwrap();
    let signature = Signature::from_bytes(
        &<[u8; 64]>::try_from(
            decode_base64url(message["signature"].as_str().unwrap()).unwrap(),
        )
        .expect("signature must contain 64 bytes"),
    );
    verifying_key.verify(&transcript, &signature).unwrap();

    let signing_key = SigningKey::from_bytes(&fixed_32(
        message["sender_signing_secret_key"].as_str().unwrap(),
    ));
    assert_eq!(
        linkdrop_protocol::encode_base64url(&signing_key.sign(&transcript).to_bytes()),
        message["signature"].as_str().unwrap()
    );

    let identity: IdentityFile =
        serde_json::from_value(message["recipient_identity"].clone()).unwrap();
    let opened = decrypt_envelope(&identity, &envelope).unwrap();
    assert_eq!(opened.signature_state, SignatureState::Verified);
    assert_eq!(
        serde_json::to_value(opened.payload).unwrap(),
        message["payload"]["json"]
    );
}

#[test]
fn invalid_model_examples_are_rejected() {
    let vectors = vectors();

    for case in vectors["invalid"]["contact_bundles"].as_array().unwrap() {
        let value: ContactBundle = serde_json::from_value(case["value"].clone()).unwrap();
        assert!(
            value.validate(false).is_err(),
            "contact case {} unexpectedly validated",
            case["name"]
        );
    }

    for case in vectors["invalid"]["public_envelopes"]
        .as_array()
        .unwrap()
    {
        let value: MessageEnvelope = serde_json::from_value(case["value"].clone()).unwrap();
        assert!(
            value.validate(false).is_err(),
            "envelope case {} unexpectedly validated",
            case["name"]
        );
    }

    for case in vectors["invalid"]["payloads"].as_array().unwrap() {
        let value: DecryptedPayload = serde_json::from_value(case["value"].clone()).unwrap();
        assert!(
            value.validate(false).is_err(),
            "payload case {} unexpectedly validated",
            case["name"]
        );
    }
}

#[test]
fn tampered_signature_is_rejected() {
    let vectors = vectors();
    let identity: IdentityFile =
        serde_json::from_value(vectors["encrypted_message"]["recipient_identity"].clone()).unwrap();
    let envelope: MessageEnvelope =
        serde_json::from_value(vectors["invalid"]["signatures"][0]["value"].clone()).unwrap();

    envelope.validate(false).unwrap();
    assert!(decrypt_envelope(&identity, &envelope).is_err());
}
