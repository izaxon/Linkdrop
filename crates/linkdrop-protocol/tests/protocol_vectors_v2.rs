use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use linkdrop_protocol::{
    decode_base64url, encode_base64url, parse_tagged_base64,
    v2::{
        ContactBundle, Envelope, Payload, PayloadContent, ReceiveProfile, chain_drop,
        derive_chain_key, derive_drop_id, open, seal_with, signature_transcript,
        verify_payload_signature,
    },
};
use serde_json::Value;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../test-vectors/v2/normative.json"))
        .expect("normative vector JSON must parse")
}

fn fixed_32(value: &str) -> [u8; 32] {
    decode_base64url(value)
        .expect("vector must be base64url")
        .try_into()
        .expect("vector must contain 32 bytes")
}

fn tagged_32(value: &str, prefix: &str) -> [u8; 32] {
    parse_tagged_base64(value, prefix)
        .expect("vector must be a tagged key")
        .try_into()
        .expect("key must contain 32 bytes")
}

fn message_vectors(vectors: &Value) -> Vec<&Value> {
    vec![
        &vectors["capability_message"],
        &vectors["chain_message"],
        &vectors["control_message"],
    ]
}

#[test]
fn valid_contact_bundle_and_payloads_match_v2_models() {
    let vectors = vectors();
    let bundle: ContactBundle =
        serde_json::from_value(vectors["contact_bundle"]["json"].clone()).unwrap();
    bundle.validate(false).unwrap();

    for message in message_vectors(&vectors) {
        let content: PayloadContent = serde_json::from_value(message["content"].clone()).unwrap();
        content.validate(false).unwrap();
        let payload: Payload = serde_json::from_value(message["payload"]["json"].clone()).unwrap();
        payload.validate(false).unwrap();
        assert_eq!(payload.content, content);
        assert_eq!(
            serde_json::to_string(&payload).unwrap(),
            message["payload"]["plaintext_utf8"].as_str().unwrap(),
            "{}",
            message["label"]
        );
        assert_eq!(
            encode_base64url(
                message["payload"]["plaintext_utf8"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
            ),
            message["payload"]["plaintext_base64url"].as_str().unwrap()
        );
        let envelope: Envelope =
            serde_json::from_value(message["public_envelope"].clone()).unwrap();
        envelope.validate().unwrap();
    }
}

#[test]
fn derived_drop_tables_match_hkdf_outputs() {
    let vectors = vectors();
    for table in vectors["derived_drops"].as_array().unwrap() {
        let profile: ReceiveProfile = serde_json::from_value(table["profile"].clone()).unwrap();
        profile.validate(false).unwrap();
        let chain_key = fixed_32(&profile.chain_key);
        for row in table["drops"].as_array().unwrap() {
            let seq = row["seq"].as_u64().unwrap();
            let mut info = b"linkdrop-v2-drop-id".to_vec();
            info.extend_from_slice(&seq.to_be_bytes());
            assert_eq!(
                format!("{seq:016x}"),
                row["info_suffix_u64be"].as_str().unwrap()
            );
            let hk = Hkdf::<Sha256>::new(None, &chain_key);
            let mut out = [0_u8; 32];
            hk.expand(&info, &mut out).unwrap();
            assert_eq!(encode_base64url(&out), row["drop_id"].as_str().unwrap());
            assert_eq!(
                derive_drop_id(&chain_key, seq),
                row["drop_id"].as_str().unwrap()
            );
            let drop = chain_drop(&profile, seq).unwrap();
            assert_eq!(drop.drop_id, row["drop_id"].as_str().unwrap());
            assert_eq!(drop.server, row["server"].as_str().unwrap());
        }
    }
}

#[test]
fn implied_generation_zero_chain_key_matches() {
    let vectors = vectors();
    let shared = fixed_32(
        vectors["capability_message"]["x25519_shared_secret"]
            .as_str()
            .unwrap(),
    );
    let drop_id = decode_base64url(
        vectors["implied_generation_0"]["hkdf_chain_key"]["salt_base64url"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let hk = Hkdf::<Sha256>::new(Some(&drop_id), &shared);
    let mut out = [0_u8; 32];
    hk.expand(b"linkdrop-v2-chain-key", &mut out).unwrap();
    assert_eq!(
        encode_base64url(&out),
        vectors["implied_generation_0"]["profile"]["chain_key"]
            .as_str()
            .unwrap()
    );
    assert_eq!(derive_chain_key(&shared, &drop_id), out);
}

#[test]
fn key_schedule_transcript_signature_and_aead_match_normative_bytes() {
    let vectors = vectors();
    for message in message_vectors(&vectors) {
        let label = message["label"].as_str().unwrap();
        let receive_secret =
            StaticSecret::from(fixed_32(message["receive_secret_key"].as_str().unwrap()));
        let receive_public = tagged_32(message["receive_key"].as_str().unwrap(), "x25519");
        assert_eq!(
            PublicKey::from(&receive_secret).as_bytes(),
            &receive_public,
            "{label}: receive key"
        );
        let ephemeral_secret = StaticSecret::from(fixed_32(
            message["sender_ephemeral_secret_key"].as_str().unwrap(),
        ));
        let ephemeral_public = tagged_32(
            message["sender_ephemeral_public_key"].as_str().unwrap(),
            "x25519",
        );
        assert_eq!(
            PublicKey::from(&ephemeral_secret).as_bytes(),
            &ephemeral_public,
            "{label}: ephemeral key"
        );

        let shared = ephemeral_secret.diffie_hellman(&PublicKey::from(receive_public));
        assert_eq!(
            receive_secret
                .diffie_hellman(&PublicKey::from(ephemeral_public))
                .as_bytes(),
            shared.as_bytes()
        );
        assert_eq!(
            encode_base64url(shared.as_bytes()),
            message["x25519_shared_secret"].as_str().unwrap(),
            "{label}: shared secret"
        );

        let drop_id_bytes = decode_base64url(message["drop"]["drop_id"].as_str().unwrap()).unwrap();
        let hk = Hkdf::<Sha256>::new(Some(&drop_id_bytes), shared.as_bytes());
        let mut key = [0_u8; 32];
        hk.expand(
            message["hkdf_message_key"]["info_utf8"]
                .as_str()
                .unwrap()
                .as_bytes(),
            &mut key,
        )
        .unwrap();
        assert_eq!(
            encode_base64url(&key),
            message["hkdf_message_key"]["message_key"].as_str().unwrap(),
            "{label}: message key"
        );

        let content: PayloadContent = serde_json::from_value(message["content"].clone()).unwrap();
        let signing_key = SigningKey::from_bytes(&fixed_32(
            message["sender_signing_secret_key"].as_str().unwrap(),
        ));
        let transcript = signature_transcript(
            &drop_id_bytes,
            &ephemeral_public,
            &receive_public,
            &content,
            signing_key.verifying_key().as_bytes(),
        );
        assert_eq!(
            encode_base64url(&transcript),
            message["signature_transcript_base64url"].as_str().unwrap(),
            "{label}: transcript"
        );
        let signature = signing_key.sign(&transcript);
        assert_eq!(
            encode_base64url(&signature.to_bytes()),
            message["signature"].as_str().unwrap(),
            "{label}: signature"
        );
        let verifying_key =
            VerifyingKey::from_bytes(signing_key.verifying_key().as_bytes()).unwrap();
        verifying_key
            .verify(
                &transcript,
                &Signature::from_bytes(
                    &decode_base64url(message["signature"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
            )
            .unwrap();

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
            encode_base64url(&ciphertext),
            message["ciphertext"].as_str().unwrap(),
            "{label}: ciphertext"
        );

        let sealed = seal_with(
            &signing_key,
            message["receive_key"].as_str().unwrap(),
            message["drop"]["drop_id"].as_str().unwrap(),
            &content,
            ephemeral_secret,
            nonce.clone().try_into().unwrap(),
        )
        .unwrap();
        let expected: Envelope =
            serde_json::from_value(message["public_envelope"].clone()).unwrap();
        assert_eq!(sealed.envelope, expected, "{label}: envelope");

        let opened = open(
            &receive_secret,
            message["drop"]["drop_id"].as_str().unwrap(),
            &expected,
        )
        .unwrap();
        assert_eq!(opened.payload.content, content, "{label}: opened content");
        assert_eq!(
            serde_json::to_value(&opened.payload).unwrap(),
            message["payload"]["json"]
        );
    }
}

#[test]
fn invalid_v2_examples_are_rejected() {
    let vectors = vectors();

    for case in vectors["invalid"]["contact_bundles"].as_array().unwrap() {
        let value: ContactBundle = serde_json::from_value(case["value"].clone()).unwrap();
        assert!(
            value.validate(false).is_err(),
            "contact case {} unexpectedly validated",
            case["name"]
        );
    }

    for case in vectors["invalid"]["public_envelopes"].as_array().unwrap() {
        let value: Envelope = serde_json::from_value(case["value"].clone()).unwrap();
        assert!(
            value.validate().is_err(),
            "envelope case {} unexpectedly validated",
            case["name"]
        );
    }

    for case in vectors["invalid"]["payload_contents"].as_array().unwrap() {
        let value: PayloadContent = serde_json::from_value(case["value"].clone()).unwrap();
        assert!(
            value.validate(false).is_err(),
            "payload case {} unexpectedly validated",
            case["name"]
        );
    }

    for case in vectors["invalid"]["signatures"].as_array().unwrap() {
        let payload: Payload = serde_json::from_value(case["payload_json"].clone()).unwrap();
        payload.validate(false).unwrap();
        let drop_id_bytes = decode_base64url(case["drop"]["drop_id"].as_str().unwrap()).unwrap();
        let ephemeral = tagged_32(
            case["sender_ephemeral_public_key"].as_str().unwrap(),
            "x25519",
        );
        let receive_secret =
            StaticSecret::from(fixed_32(case["receive_secret_key"].as_str().unwrap()));
        assert!(
            verify_payload_signature(
                &drop_id_bytes,
                &ephemeral,
                PublicKey::from(&receive_secret).as_bytes(),
                &payload
            )
            .is_err(),
            "signature case {} unexpectedly verified",
            case["name"]
        );
    }
}

#[test]
fn envelope_does_not_decrypt_under_another_drop_id() {
    let vectors = vectors();
    let message = &vectors["capability_message"];
    let receive_secret =
        StaticSecret::from(fixed_32(message["receive_secret_key"].as_str().unwrap()));
    let envelope: Envelope = serde_json::from_value(message["public_envelope"].clone()).unwrap();
    let other_drop = vectors["chain_message"]["drop"]["drop_id"]
        .as_str()
        .unwrap();
    assert!(open(&receive_secret, other_drop, &envelope).is_err());
}
