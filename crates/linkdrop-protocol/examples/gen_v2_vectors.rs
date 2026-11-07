//! Regenerates `test-vectors/v2/normative.json` from fixed test-only inputs.
//!
//! Run from the workspace root:
//! `cargo run -p linkdrop-protocol --example gen_v2_vectors > test-vectors/v2/normative.json`
//!
//! The inputs are deliberately public. Never use them in a real message.

use ed25519_dalek::SigningKey;
use linkdrop_protocol::{
    decode_base64url, encode_base64url, tagged_base64,
    v2::{
        ContactBundle, DropCapability, MessageType, PayloadContent, ReceiveProfile, chain_drop,
        derive_chain_key, derive_drop_id, derive_message_key, seal_with, signature_transcript,
    },
};
use serde_json::{Value, json};
use x25519_dalek::{PublicKey, StaticSecret};

fn pattern(start: u8) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = start.wrapping_add(index as u8);
    }
    out
}

fn x25519_pair(seed: u8) -> (StaticSecret, String) {
    let secret = StaticSecret::from(pattern(seed));
    let public = tagged_base64("x25519", PublicKey::from(&secret).as_bytes());
    (secret, public)
}

struct Message {
    label: &'static str,
    drop: linkdrop_protocol::DropRef,
    receive_key: String,
    receive_secret_seed: u8,
    ephemeral_seed: u8,
    nonce_seed: u8,
    content: PayloadContent,
}

fn message_vector(signing_key: &SigningKey, signing_seed: u8, message: &Message) -> Value {
    let ephemeral = StaticSecret::from(pattern(message.ephemeral_seed));
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&pattern(message.nonce_seed)[..12]);
    let sealed = seal_with(
        signing_key,
        &message.receive_key,
        &message.drop.drop_id,
        &message.content,
        ephemeral.clone(),
        nonce,
    )
    .expect("vector sealing must succeed");
    let drop_id_bytes = decode_base64url(&message.drop.drop_id).unwrap();
    let receive_public = decode_base64url(message.receive_key.split_once(':').unwrap().1).unwrap();
    let transcript = signature_transcript(
        &drop_id_bytes,
        PublicKey::from(&ephemeral).as_bytes(),
        &receive_public.clone().try_into().unwrap(),
        &message.content,
        signing_key.verifying_key().as_bytes(),
    );
    let message_key = derive_message_key(&sealed.shared_secret, &drop_id_bytes);
    let payload: Value = serde_json::from_slice(&sealed.plaintext).unwrap();
    json!({
        "label": message.label,
        "drop": message.drop,
        "receive_key": message.receive_key,
        "receive_secret_key": encode_base64url(&pattern(message.receive_secret_seed)),
        "sender_signing_secret_key": encode_base64url(&pattern(signing_seed)),
        "sender_ephemeral_secret_key": encode_base64url(&pattern(message.ephemeral_seed)),
        "sender_ephemeral_public_key": sealed.envelope.sender_ephemeral_key,
        "x25519_shared_secret": encode_base64url(&sealed.shared_secret),
        "hkdf_message_key": {
            "hash": "SHA-256",
            "salt_base64url": message.drop.drop_id,
            "info_utf8": "linkdrop-v2-message-key",
            "output_length": 32,
            "message_key": encode_base64url(&message_key)
        },
        "content": message.content,
        "signature_transcript_base64url": encode_base64url(&transcript),
        "signature": payload["signature"],
        "payload": {
            "json": payload,
            "plaintext_utf8": String::from_utf8(sealed.plaintext.clone()).unwrap(),
            "plaintext_base64url": encode_base64url(&sealed.plaintext)
        },
        "nonce": sealed.envelope.nonce,
        "ciphertext": sealed.envelope.ciphertext,
        "public_envelope": sealed.envelope
    })
}

fn main() {
    // Bob owns the bundle. Alice writes the capability message.
    let bob_signing = SigningKey::from_bytes(&pattern(0x60));
    let alice_signing = SigningKey::from_bytes(&pattern(0x00));
    let (_, bob_capability_public) = x25519_pair(0x24);
    let capability_drop_id = encode_base64url(&pattern(0x80));
    let bundle = ContactBundle {
        v: 2,
        display_name: Some("Bob".to_string()),
        identity_key: tagged_base64("ed25519", bob_signing.verifying_key().as_bytes()),
        initial: vec![DropCapability {
            server: "https://drop.example".to_string(),
            drop_id: capability_drop_id.clone(),
            recipient_key: bob_capability_public.clone(),
        }],
    };
    bundle.validate(false).unwrap();

    // Alice's receive profile (Bob -> Alice, gen 0) and rescue.
    let (_, alice_receive_public) = x25519_pair(0xa0);
    let alice_profile = ReceiveProfile {
        generation: 0,
        chain_key: encode_base64url(&pattern(0xc0)),
        receive_key: alice_receive_public.clone(),
        servers: vec![
            "https://a.example".to_string(),
            "https://b.example".to_string(),
        ],
    };
    let (_, alice_rescue_public) = x25519_pair(0xe0);
    let alice_rescue = DropCapability {
        server: "https://b.example".to_string(),
        drop_id: encode_base64url(&pattern(0x10)),
        recipient_key: alice_rescue_public,
    };

    let capability_message = Message {
        label: "Alice -> Bob capability message on the bundle's initial capability (seq 0)",
        drop: linkdrop_protocol::DropRef {
            server: "https://drop.example".to_string(),
            drop_id: capability_drop_id.clone(),
        },
        receive_key: bob_capability_public,
        receive_secret_seed: 0x24,
        ephemeral_seed: 0x44,
        nonce_seed: 0x00,
        content: PayloadContent {
            message_type: MessageType::Text,
            msg_id: encode_base64url(&pattern(0x70)[..16]),
            created_at: 1_777_000_100,
            seq: 0,
            text: Some("Hello from the V2 draft".to_string()),
            ack: None,
            missing: None,
            resend_of: None,
            receive: Some(alice_profile.clone()),
            rescue: Some(alice_rescue),
        },
    };
    let capability_vector = message_vector(&alice_signing, 0x00, &capability_message);

    // Alice -> Bob generation 0 is implied by the capability message.
    let shared = decode_base64url(capability_vector["x25519_shared_secret"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let alice_to_bob_chain_key = derive_chain_key(&shared, &pattern(0x80));
    let alice_to_bob_profile = ReceiveProfile {
        generation: 0,
        chain_key: encode_base64url(&alice_to_bob_chain_key),
        receive_key: capability_message.receive_key.clone(),
        servers: vec!["https://drop.example".to_string()],
    };

    // Bob replies on Alice's profile: seq 0 of Bob -> Alice, acknowledging Alice's seq 0 and
    // rotating Alice -> Bob to generation 1.
    let (_, bob_gen1_receive_public) = x25519_pair(0x70);
    let bob_gen1_profile = ReceiveProfile {
        generation: 1,
        chain_key: encode_base64url(&pattern(0x30)),
        receive_key: bob_gen1_receive_public,
        servers: vec!["https://drop.example".to_string()],
    };
    let (_, bob_rescue_public) = x25519_pair(0x90);
    let reply_drop = chain_drop(&alice_profile, 0).unwrap();
    let reply_message = Message {
        label: "Bob -> Alice chain message on Alice's gen 0 profile (seq 0, ack 0, rotates Alice -> Bob to gen 1)",
        drop: reply_drop,
        receive_key: alice_receive_public,
        receive_secret_seed: 0xa0,
        ephemeral_seed: 0x50,
        nonce_seed: 0x10,
        content: PayloadContent {
            message_type: MessageType::Text,
            msg_id: encode_base64url(&pattern(0x90)[..16]),
            created_at: 1_777_000_200,
            seq: 0,
            text: Some("Hi Alice".to_string()),
            ack: Some(0),
            missing: None,
            resend_of: None,
            receive: Some(bob_gen1_profile),
            rescue: Some(DropCapability {
                server: "https://drop.example".to_string(),
                drop_id: encode_base64url(&pattern(0xb0)),
                recipient_key: bob_rescue_public,
            }),
        },
    };
    let reply_vector = message_vector(&bob_signing, 0x60, &reply_message);

    // A control message with a gap report, to pin the transcript encoding of ack/missing/resend_of.
    let control_drop = chain_drop(&alice_to_bob_profile, 3).unwrap();
    let control_message = Message {
        label: "Alice -> Bob control message on implied gen 0 (seq 3, ack 4, missing [1, 2], resend_of 2)",
        drop: control_drop,
        receive_key: alice_to_bob_profile.receive_key.clone(),
        receive_secret_seed: 0x24,
        ephemeral_seed: 0x48,
        nonce_seed: 0x20,
        content: PayloadContent {
            message_type: MessageType::Control,
            msg_id: encode_base64url(&pattern(0xd0)[..16]),
            created_at: 1_777_000_300,
            seq: 3,
            text: None,
            ack: Some(4),
            missing: Some(vec![1, 2]),
            resend_of: Some(2),
            receive: None,
            rescue: None,
        },
    };
    let control_vector = message_vector(&alice_signing, 0x00, &control_message);

    let derived = |profile: &ReceiveProfile, label: &str| {
        let chain_key: [u8; 32] = decode_base64url(&profile.chain_key)
            .unwrap()
            .try_into()
            .unwrap();
        json!({
            "label": label,
            "profile": profile,
            "drops": (0..4u64).map(|seq| json!({
                "seq": seq,
                "info_utf8_prefix": "linkdrop-v2-drop-id",
                "info_suffix_u64be": format!("{seq:016x}"),
                "drop_id": derive_drop_id(&chain_key, seq),
                "server": profile.servers[(seq % profile.servers.len() as u64) as usize]
            })).collect::<Vec<_>>()
        })
    };

    let invalid = json!({
        "contact_bundles": [
            { "name": "wrong version", "value": { "v": 1, "identity_key": bundle.identity_key, "initial": bundle.initial } },
            { "name": "empty initial", "value": { "v": 2, "identity_key": bundle.identity_key, "initial": [] } },
            { "name": "duplicate drop ids", "value": { "v": 2, "identity_key": bundle.identity_key, "initial": [bundle.initial[0], bundle.initial[0]] } },
            { "name": "capability without recipient key", "value": { "v": 2, "identity_key": bundle.identity_key, "initial": [{ "server": "https://drop.example", "drop_id": capability_drop_id, "recipient_key": "x25519:AAEC" }] } },
            { "name": "http server outside loopback", "value": { "v": 2, "identity_key": bundle.identity_key, "initial": [{ "server": "http://drop.example", "drop_id": capability_drop_id, "recipient_key": bundle.initial[0].recipient_key }] } }
        ],
        "public_envelopes": [
            { "name": "wrong version", "value": { "v": 1, "sender_ephemeral_key": capability_vector["public_envelope"]["sender_ephemeral_key"], "nonce": capability_vector["nonce"], "ciphertext": capability_vector["ciphertext"] } },
            { "name": "short nonce", "value": { "v": 2, "sender_ephemeral_key": capability_vector["public_envelope"]["sender_ephemeral_key"], "nonce": "AAECAwQFBgcICQo", "ciphertext": capability_vector["ciphertext"] } },
            { "name": "tag-only ciphertext", "value": { "v": 2, "sender_ephemeral_key": capability_vector["public_envelope"]["sender_ephemeral_key"], "nonce": capability_vector["nonce"], "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA" } },
            { "name": "ed25519 ephemeral key", "value": { "v": 2, "sender_ephemeral_key": bundle.identity_key, "nonce": capability_vector["nonce"], "ciphertext": capability_vector["ciphertext"] } }
        ],
        "payload_contents": [
            { "name": "text message without text", "value": { "type": "text", "msg_id": "cHFyc3R1dnd4eXp7fH1-fw", "created_at": 1, "seq": 0 } },
            { "name": "control message with text", "value": { "type": "control", "msg_id": "cHFyc3R1dnd4eXp7fH1-fw", "created_at": 1, "seq": 0, "text": "x" } },
            { "name": "missing without ack", "value": { "type": "control", "msg_id": "cHFyc3R1dnd4eXp7fH1-fw", "created_at": 1, "seq": 0, "missing": [0] } },
            { "name": "missing not below ack", "value": { "type": "control", "msg_id": "cHFyc3R1dnd4eXp7fH1-fw", "created_at": 1, "seq": 0, "ack": 2, "missing": [2] } },
            { "name": "missing not increasing", "value": { "type": "control", "msg_id": "cHFyc3R1dnd4eXp7fH1-fw", "created_at": 1, "seq": 0, "ack": 5, "missing": [3, 3] } },
            { "name": "empty missing", "value": { "type": "control", "msg_id": "cHFyc3R1dnd4eXp7fH1-fw", "created_at": 1, "seq": 0, "ack": 5, "missing": [] } },
            { "name": "resend_of not below seq", "value": { "type": "control", "msg_id": "cHFyc3R1dnd4eXp7fH1-fw", "created_at": 1, "seq": 4, "resend_of": 4 } },
            { "name": "seq above 2^53", "value": { "type": "control", "msg_id": "cHFyc3R1dnd4eXp7fH1-fw", "created_at": 1, "seq": 9007199254740992u64 } },
            { "name": "receive profile with short chain key", "value": { "type": "control", "msg_id": "cHFyc3R1dnd4eXp7fH1-fw", "created_at": 1, "seq": 0, "receive": { "gen": 1, "chain_key": "AAEC", "receive_key": alice_profile.receive_key, "servers": ["https://a.example"] } } },
            { "name": "receive profile without servers", "value": { "type": "control", "msg_id": "cHFyc3R1dnd4eXp7fH1-fw", "created_at": 1, "seq": 0, "receive": { "gen": 1, "chain_key": alice_profile.chain_key, "receive_key": alice_profile.receive_key, "servers": [] } } },
            { "name": "receive profile with duplicate servers", "value": { "type": "control", "msg_id": "cHFyc3R1dnd4eXp7fH1-fw", "created_at": 1, "seq": 0, "receive": { "gen": 1, "chain_key": alice_profile.chain_key, "receive_key": alice_profile.receive_key, "servers": ["https://a.example", "https://a.example"] } } }
        ],
        "signatures": [
            {
                "name": "flipped signature bit in the capability message plaintext",
                "drop": capability_vector["drop"],
                "receive_secret_key": capability_vector["receive_secret_key"],
                "sender_ephemeral_public_key": capability_vector["sender_ephemeral_public_key"],
                "payload_json": {
                    "type": "text",
                    "msg_id": capability_vector["content"]["msg_id"],
                    "created_at": capability_vector["content"]["created_at"],
                    "seq": 0,
                    "text": capability_vector["content"]["text"],
                    "receive": capability_vector["content"]["receive"],
                    "rescue": capability_vector["content"]["rescue"],
                    "sender_identity_key": capability_vector["payload"]["json"]["sender_identity_key"],
                    "signature": flip_first_bit(capability_vector["signature"].as_str().unwrap())
                }
            }
        ]
    });

    let vectors = json!({
        "schema": "linkdrop-test-vectors-v2-draft",
        "protocol_version": 2,
        "status": "draft",
        "contact_bundle": {
            "owner_signing_secret_key": encode_base64url(&pattern(0x60)),
            "initial_capability_secret_key": encode_base64url(&pattern(0x24)),
            "json": bundle
        },
        "capability_message": capability_vector,
        "implied_generation_0": {
            "hkdf_chain_key": {
                "hash": "SHA-256",
                "ikm": "x25519_shared_secret of the capability message",
                "salt_base64url": capability_drop_id,
                "info_utf8": "linkdrop-v2-chain-key",
                "output_length": 32
            },
            "profile": alice_to_bob_profile
        },
        "derived_drops": [
            derived(&alice_to_bob_profile, "Alice -> Bob implied generation 0"),
            derived(&alice_profile, "Bob -> Alice generation 0 from the capability message's receive profile")
        ],
        "chain_message": reply_vector,
        "control_message": control_vector,
        "invalid": invalid
    });
    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}

fn flip_first_bit(signature: &str) -> String {
    let mut bytes = decode_base64url(signature).unwrap();
    bytes[0] ^= 0x01;
    encode_base64url(&bytes)
}
