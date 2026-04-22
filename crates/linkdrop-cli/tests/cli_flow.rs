use std::{fs, path::Path};

use anyhow::Result;
use axum::{
    Router,
    http::StatusCode,
    routing::head,
};
use linkdrop_cli::LinkdropApp;
use linkdrop_protocol::{
    ClientStateFile, ContactsFile, DecryptedPayload, DropRef, IdentityFile, MessageDirection,
    MessageStatus, WatchedDrop, encrypt_payload_for_contact,
};
use linkdrop_server::spawn_test_server;
use tempfile::TempDir;

fn write_bundle(path: &Path, bundle: &linkdrop_protocol::ContactBundle) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(bundle)?)?;
    Ok(())
}

fn read_contacts(path: &Path) -> Result<ContactsFile> {
    Ok(serde_json::from_str(&fs::read_to_string(
        path.join("contacts.json"),
    )?)?)
}

fn read_client_state(path: &Path) -> Result<ClientStateFile> {
    Ok(serde_json::from_str(&fs::read_to_string(
        path.join("client.json"),
    )?)?)
}

#[test]
fn identity_generation_succeeds() -> Result<()> {
    let temp = TempDir::new()?;
    let app = LinkdropApp::new(temp.path())?;

    let identity = app.init("Alice")?;
    let loaded = app.whoami()?;

    assert_eq!(identity.display_name, "Alice");
    assert_eq!(loaded.display_name, "Alice");
    assert!(temp.path().join("identity.json").exists());
    Ok(())
}

#[test]
fn contact_bundle_export_import_round_trips() -> Result<()> {
    let alice_dir = TempDir::new()?;
    let bob_dir = TempDir::new()?;
    let alice = LinkdropApp::new(alice_dir.path())?;
    let bob = LinkdropApp::new(bob_dir.path())?;
    alice.init("Alice")?;
    bob.init("Bob")?;

    let bundle = alice.export_contact_bundle(&["http://127.0.0.1:9000".to_string()])?;
    let bundle_path = alice_dir.path().join("alice-bundle.json");
    write_bundle(&bundle_path, &bundle)?;
    let imported = bob.import_contact_bundle(&bundle_path)?;

    assert_eq!(imported.identity_key, bundle.identity_key);
    assert_eq!(imported.prekey.as_deref(), Some(bundle.prekey.as_str()));
    assert_eq!(imported.initial_drops, bundle.initial_drops);
    Ok(())
}

#[test]
fn message_encryption_decryption_round_trips() -> Result<()> {
    let alice = IdentityFile::generate("Alice");
    let bob = IdentityFile::generate("Bob");
    let reply_drop = DropRef {
        server: "http://127.0.0.1:9000".to_string(),
        drop_id: linkdrop_protocol::generate_drop_id(),
    };
    let payload = DecryptedPayload {
        text: "Hej".to_string(),
        prev_msg_id: None,
    };

    let envelope = encrypt_payload_for_contact(
        &alice,
        &bob.tagged_prekey_public_key(),
        reply_drop,
        &payload,
    )?;
    let decrypted = linkdrop_protocol::decrypt_envelope(&bob, &envelope)?;

    assert_eq!(decrypted.text, "Hej");
    Ok(())
}

#[test]
fn fresh_reply_drop_is_generated_for_each_outbound_message() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let server_dir = TempDir::new()?;
    let (server, handle) = runtime.block_on(spawn_test_server(
        server_dir.path().join("server.db"),
        16 * 1024,
    ))?;

    {
        let alice_dir = TempDir::new()?;
        let bob_dir = TempDir::new()?;
        let alice = LinkdropApp::new(alice_dir.path())?;
        let bob = LinkdropApp::new(bob_dir.path())?;
        alice.init("Alice")?;
        bob.init("Bob")?;

        let bundle = bob.export_contact_bundle(&[server.clone(), server.clone()])?;
        let bundle_path = server_dir.path().join("bob-bundle.json");
        write_bundle(&bundle_path, &bundle)?;
        let bob_contact = alice.import_contact_bundle(&bundle_path)?;

        let first = alice.send_message(&bob_contact.contact_id, "one")?;
        let second = alice.send_message(&bob_contact.contact_id, "two")?;
        assert_ne!(first.reply_drop_generated, second.reply_drop_generated);
    }

    handle.abort();
    Ok(())
}

#[test]
fn duplicate_msg_id_is_ignored() -> Result<()> {
    let bob_dir = TempDir::new()?;
    let bob = LinkdropApp::new(bob_dir.path())?;
    bob.init("Bob")?;

    let alice = IdentityFile::generate("Alice");
    let watch = WatchedDrop {
        drop: DropRef {
            server: "http://127.0.0.1:9000".to_string(),
            drop_id: linkdrop_protocol::generate_drop_id(),
        },
        contact_id: None,
    };
    let payload = DecryptedPayload {
        text: "hello".to_string(),
        prev_msg_id: None,
    };
    let envelope = encrypt_payload_for_contact(
        &alice,
        &bob.whoami()?.tagged_prekey_public_key(),
        DropRef {
            server: "http://127.0.0.1:9000".to_string(),
            drop_id: linkdrop_protocol::generate_drop_id(),
        },
        &payload,
    )?;

    let first = bob.process_incoming_envelope(watch.clone(), envelope.clone())?;
    let second = bob.process_incoming_envelope(watch, envelope)?;
    let inbox = bob.inbox()?;

    assert_eq!(first.received, 1);
    assert_eq!(second.duplicates, 1);
    assert_eq!(inbox.len(), 1);
    Ok(())
}

#[test]
fn duplicate_msg_id_does_not_overwrite_next_outgoing_drop() -> Result<()> {
    let bob_dir = TempDir::new()?;
    let bob = LinkdropApp::new(bob_dir.path())?;
    bob.init("Bob")?;

    let alice = IdentityFile::generate("Alice");
    let watch = WatchedDrop {
        drop: DropRef {
            server: "http://127.0.0.1:9000".to_string(),
            drop_id: linkdrop_protocol::generate_drop_id(),
        },
        contact_id: None,
    };
    let payload = DecryptedPayload {
        text: "hello".to_string(),
        prev_msg_id: None,
    };
    let first_reply_drop = DropRef {
        server: "http://127.0.0.1:9000".to_string(),
        drop_id: linkdrop_protocol::generate_drop_id(),
    };
    let mut duplicate_reply_drop = first_reply_drop.clone();
    duplicate_reply_drop.drop_id = linkdrop_protocol::generate_drop_id();

    let envelope = encrypt_payload_for_contact(
        &alice,
        &bob.whoami()?.tagged_prekey_public_key(),
        first_reply_drop.clone(),
        &payload,
    )?;
    let mut duplicate = envelope.clone();
    duplicate.reply_drop = duplicate_reply_drop;

    let _ = bob.process_incoming_envelope(watch.clone(), envelope)?;
    let _ = bob.process_incoming_envelope(watch, duplicate)?;
    let contacts = read_contacts(bob_dir.path())?;

    assert_eq!(contacts.contacts.len(), 1);
    assert_eq!(
        contacts.contacts[0].next_outgoing_drop.as_ref(),
        Some(&first_reply_drop)
    );
    Ok(())
}

#[test]
fn poll_keeps_watched_drop_when_head_and_get_disagree() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
    let address = listener.local_addr()?;
    let app = Router::new().route(
        "/drop/{drop_id}",
        head(|| async { StatusCode::OK }).get(|| async { StatusCode::NOT_FOUND }),
    );
    let handle = runtime.spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("race test server should run");
    });

    {
        let state_dir = TempDir::new()?;
        let app = LinkdropApp::new(state_dir.path())?;
        app.init("Alice")?;
        let _bundle = app.export_contact_bundle(&[format!("http://{}", address)])?;

        let summary = app.poll()?;
        let client_state = read_client_state(state_dir.path())?;

        assert_eq!(summary.received, 0);
        assert_eq!(summary.duplicates, 0);
        assert_eq!(summary.invalid, 0);
        assert_eq!(client_state.watched_drops.len(), 1);
    }

    handle.abort();
    Ok(())
}

#[test]
fn send_to_valid_initial_drop_succeeds_end_to_end() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let server_dir = TempDir::new()?;
    let (server, handle) = runtime.block_on(spawn_test_server(
        server_dir.path().join("server.db"),
        16 * 1024,
    ))?;

    {
        let alice_dir = TempDir::new()?;
        let bob_dir = TempDir::new()?;
        let alice = LinkdropApp::new(alice_dir.path())?;
        let bob = LinkdropApp::new(bob_dir.path())?;
        alice.init("Alice")?;
        bob.init("Bob")?;

        let alice_bundle = alice.export_contact_bundle(&[server.clone()])?;
        let bob_bundle = bob.export_contact_bundle(&[server.clone()])?;
        let alice_bundle_path = server_dir.path().join("alice-bundle.json");
        let bob_bundle_path = server_dir.path().join("bob-bundle.json");
        write_bundle(&alice_bundle_path, &alice_bundle)?;
        write_bundle(&bob_bundle_path, &bob_bundle)?;

        let alice_contact = bob.import_contact_bundle(&alice_bundle_path)?;
        let bob_contact = alice.import_contact_bundle(&bob_bundle_path)?;

        let sent = alice.send_message(&bob_contact.contact_id, "hello bob")?;
        let poll = bob.poll()?;
        let inbox = bob.inbox()?;
        let bob_reply = bob.send_message(&alice_contact.contact_id, "hello alice")?;
        let poll_back = alice.poll()?;
        let history = alice.history(&bob_contact.contact_id)?;

        assert_eq!(sent.status, MessageStatus::Sent);
        assert_eq!(poll.received, 1);
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].direction, MessageDirection::Inbound);
        assert_eq!(bob_reply.status, MessageStatus::Sent);
        assert_eq!(poll_back.received, 1);
        assert_eq!(history.len(), 2);
    }

    handle.abort();
    Ok(())
}
