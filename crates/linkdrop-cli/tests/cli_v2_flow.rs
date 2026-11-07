use std::{fs, path::Path, time::Duration};

use anyhow::Result;
use linkdrop_cli::{LinkdropApp, V2Status};
use linkdrop_server::{ServerOptions, spawn_test_server_with};
use tempfile::TempDir;

struct Fixture {
    _runtime: tokio::runtime::Runtime,
    _server_dir: TempDir,
    database: std::path::PathBuf,
    server: String,
    handle: tokio::task::JoinHandle<()>,
    alice_dir: TempDir,
    bob_dir: TempDir,
    alice: LinkdropApp,
    bob: LinkdropApp,
    bob_contact: String,
}

impl Fixture {
    fn new() -> Result<Self> {
        let runtime = tokio::runtime::Runtime::new()?;
        let server_dir = TempDir::new()?;
        let database = server_dir.path().join("server.db");
        let (server, handle) = runtime.block_on(spawn_test_server_with(
            database.clone(),
            ServerOptions {
                max_body_size: 16 * 1024,
                max_wait_seconds: 5,
            },
        ))?;
        let alice_dir = TempDir::new()?;
        let bob_dir = TempDir::new()?;
        let alice = LinkdropApp::new(alice_dir.path())?;
        let bob = LinkdropApp::new(bob_dir.path())?;
        alice.init("Alice")?;
        bob.init("Bob")?;
        alice.add_server(&server)?;
        bob.add_server(&server)?;

        let bundle = bob.v2_export_bundle(&[])?;
        let bundle_path = server_dir.path().join("bob-v2-bundle.json");
        fs::write(&bundle_path, serde_json::to_string_pretty(&bundle)?)?;
        let bob_contact = alice.v2_import_bundle(&bundle_path)?.contact_id;

        Ok(Self {
            _runtime: runtime,
            _server_dir: server_dir,
            database,
            server,
            handle,
            alice_dir,
            bob_dir,
            alice,
            bob,
            bob_contact,
        })
    }

    fn alice_contact_at_bob(&self) -> Result<String> {
        Ok(self.bob.v2_list_conversations()?[0].contact_id.clone())
    }

    fn delete_drop(&self, drop_id: &str) -> Result<()> {
        let conn = rusqlite::Connection::open(&self.database)?;
        conn.execute(
            "DELETE FROM drops WHERE drop_id = ?1",
            rusqlite::params![drop_id],
        )?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn conversations_file_exists(dir: &Path) -> bool {
    dir.join("conversations.json").exists()
}

#[test]
fn v2_consecutive_sends_window_poll_ack_and_rotation() -> Result<()> {
    let fixture = Fixture::new()?;
    let Fixture {
        alice,
        bob,
        bob_contact,
        ..
    } = &fixture;

    let first = alice.v2_send(bob_contact, "one")?;
    let second = alice.v2_send(bob_contact, "two")?;
    let third = alice.v2_send(bob_contact, "three")?;
    assert_eq!((first.seq, second.seq, third.seq), (0, 1, 2));

    let bob_poll = bob.v2_poll(None)?;
    assert_eq!(bob_poll.new_contacts, 1);
    assert_eq!(bob_poll.received, 3);
    let inbox = bob.v2_inbox()?;
    assert_eq!(
        inbox
            .iter()
            .map(|m| m.text.clone().unwrap())
            .collect::<Vec<_>>(),
        vec!["one", "two", "three"]
    );
    let bob_view = &bob.v2_list_conversations()?[0];
    assert!(
        !bob_view.verified,
        "first contact is unverified until confirmed"
    );
    assert_eq!(bob_view.recv.next_seq, 3);

    let alice_contact = fixture.alice_contact_at_bob()?;
    bob.v2_send(&alice_contact, "got all three")?;
    let alice_poll = alice.v2_poll(None)?;
    assert_eq!(alice_poll.received, 1);
    assert_eq!(alice_poll.delivered, 3);
    let alice_view = &alice.v2_list_conversations()?[0];
    assert!(alice_view.send.outbox.is_empty());
    assert!(
        alice
            .v2_history(bob_contact)?
            .iter()
            .filter(|m| m.direction == linkdrop_cli::V2Direction::Outbound)
            .all(|m| m.status == V2Status::Delivered)
    );

    // A long run after rotation is drained in a single poll even though the window is 8.
    for i in 0..12 {
        alice.v2_send(bob_contact, &format!("burst {i}"))?;
    }
    let bob_poll = bob.v2_poll(None)?;
    assert_eq!(bob_poll.received, 12);
    assert_eq!(bob.v2_inbox()?.len(), 15);
    let bob_view = &bob.v2_list_conversations()?[0];
    assert_eq!(bob_view.recv.generations.len(), 1);
    assert_eq!(bob_view.recv.generations[0].generation, 1);

    assert!(conversations_file_exists(fixture.alice_dir.path()));
    assert!(conversations_file_exists(fixture.bob_dir.path()));
    Ok(())
}

#[test]
fn v2_expired_drop_is_reported_and_resent_without_a_new_bundle() -> Result<()> {
    let fixture = Fixture::new()?;
    let Fixture {
        alice,
        bob,
        bob_contact,
        ..
    } = &fixture;

    alice.v2_send(bob_contact, "hello")?;
    bob.v2_poll(None)?;
    let alice_contact = fixture.alice_contact_at_bob()?;
    bob.v2_send(&alice_contact, "hi")?;
    alice.v2_poll(None)?;

    let lost = alice.v2_send(bob_contact, "lost in the mail")?;
    alice.v2_send(bob_contact, "arrives fine")?;
    let lost_drop = alice.v2_list_conversations()?[0]
        .send
        .outbox
        .iter()
        .find(|entry| entry.msg_id == lost.msg_id)
        .map(|entry| entry.drop.drop_id.clone())
        .expect("lost message is in the outbox");
    fixture.delete_drop(&lost_drop)?;

    let bob_poll = bob.v2_poll(None)?;
    assert_eq!(bob_poll.received, 1);
    assert_eq!(bob_poll.missing, 1);
    assert_eq!(
        bob_poll.control_sent, 1,
        "gap is reported without user text"
    );

    let alice_poll = alice.v2_poll(None)?;
    assert_eq!(alice_poll.resent, 1);
    let history = alice.v2_history(bob_contact)?;
    let record = history
        .iter()
        .find(|m| m.msg_id == lost.msg_id)
        .expect("record kept");
    assert_eq!(record.resends, 1);
    assert_eq!(record.status, V2Status::Sent);

    let bob_poll = bob.v2_poll(None)?;
    assert_eq!(bob_poll.received, 1);
    let texts: Vec<_> = bob.v2_inbox()?.into_iter().filter_map(|m| m.text).collect();
    assert_eq!(
        texts,
        vec!["hello", "arrives fine", "lost in the mail"],
        "delivered in arrival order; the resend fills the gap"
    );
    assert!(bob.v2_list_conversations()?[0].recv.missing.is_empty());
    Ok(())
}

#[test]
fn v2_long_poll_wakes_a_waiting_receiver() -> Result<()> {
    let fixture = Fixture::new()?;
    let Fixture {
        alice,
        bob,
        bob_contact,
        server,
        ..
    } = &fixture;
    assert!(server.starts_with("http://127.0.0.1:"));

    alice.v2_send(bob_contact, "open")?;
    bob.v2_poll(None)?;

    let waiting_bob = LinkdropApp::new(fixture.bob_dir.path())?;
    let waiter = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let summary = waiting_bob.v2_poll(Some(4)).expect("poll succeeds");
        (summary, started.elapsed())
    });
    std::thread::sleep(Duration::from_millis(400));
    alice.v2_send(bob_contact, "wake up")?;
    let (summary, elapsed) = waiter.join().expect("waiter thread");

    assert_eq!(summary.received, 1);
    assert!(
        elapsed < Duration::from_secs(4),
        "long poll returned early on write ({elapsed:?})"
    );
    assert_eq!(
        bob.v2_inbox()?
            .last()
            .and_then(|m| m.text.clone())
            .as_deref(),
        Some("wake up")
    );
    Ok(())
}

#[test]
fn v2_state_does_not_touch_v1_files() -> Result<()> {
    let fixture = Fixture::new()?;
    let before = fs::read_to_string(fixture.alice_dir.path().join("contacts.json"))?;
    fixture.alice.v2_send(&fixture.bob_contact, "v2 only")?;
    let after = fs::read_to_string(fixture.alice_dir.path().join("contacts.json"))?;
    assert_eq!(before, after);
    assert!(fixture.alice.list_contacts()?.is_empty());
    Ok(())
}
