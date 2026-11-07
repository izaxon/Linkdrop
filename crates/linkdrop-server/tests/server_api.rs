use anyhow::Result;
use linkdrop_protocol::{
    DecryptedPayload, DropRef, IdentityFile, encrypt_payload_for_contact, generate_drop_id,
};
use linkdrop_server::spawn_test_server;
use reqwest::StatusCode;
use tempfile::TempDir;

fn sample_envelope(server: &str) -> String {
    let identity = IdentityFile::generate("Alice");
    let reply_drop = DropRef {
        server: server.to_string(),
        drop_id: generate_drop_id(),
    };
    let payload = DecryptedPayload {
        text: "hello".to_string(),
        reply_drop,
        prev_msg_id: None,
    };
    let envelope = encrypt_payload_for_contact(
        &identity,
        &identity.tagged_prekey_public_key(),
        &payload,
        true,
    )
    .unwrap();
    serde_json::to_string(&envelope).unwrap()
}

#[tokio::test]
async fn put_to_unused_drop_returns_201_and_second_put_returns_409() -> Result<()> {
    let temp = TempDir::new()?;
    let (server, handle) = spawn_test_server(temp.path().join("server.db"), 16 * 1024).await?;
    let client = reqwest::Client::new();
    let drop_id = generate_drop_id();
    let body = sample_envelope(&server);

    let first = client
        .put(format!("{server}/drop/{drop_id}"))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await?;
    let second = client
        .put(format!("{server}/drop/{drop_id}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await?;

    handle.abort();
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(second.status(), StatusCode::CONFLICT);
    Ok(())
}

#[tokio::test]
async fn get_to_used_drop_returns_stored_body_and_unused_returns_404() -> Result<()> {
    let temp = TempDir::new()?;
    let (server, handle) = spawn_test_server(temp.path().join("server.db"), 16 * 1024).await?;
    let client = reqwest::Client::new();
    let drop_id = generate_drop_id();
    let body = sample_envelope(&server);

    client
        .put(format!("{server}/drop/{drop_id}"))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await?;

    let found = client
        .get(format!("{server}/drop/{drop_id}"))
        .send()
        .await?;
    let missing = client
        .get(format!("{server}/drop/{}", generate_drop_id()))
        .send()
        .await?;

    handle.abort();
    assert_eq!(found.status(), StatusCode::OK);
    assert_eq!(found.text().await?, body);
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn head_returns_200_for_used_drop_and_404_for_unused_drop() -> Result<()> {
    let temp = TempDir::new()?;
    let (server, handle) = spawn_test_server(temp.path().join("server.db"), 16 * 1024).await?;
    let client = reqwest::Client::new();
    let drop_id = generate_drop_id();
    let body = sample_envelope(&server);

    client
        .put(format!("{server}/drop/{drop_id}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await?;

    let found = client
        .head(format!("{server}/drop/{drop_id}"))
        .send()
        .await?;
    let missing = client
        .head(format!("{server}/drop/{}", generate_drop_id()))
        .send()
        .await?;

    handle.abort();
    assert_eq!(found.status(), StatusCode::OK);
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    Ok(())
}

fn sample_v2_envelope() -> (String, String) {
    use ed25519_dalek::SigningKey;
    use linkdrop_protocol::v2::{MessageType, OwnedCapability, PayloadContent, seal};

    let capability = OwnedCapability::generate("https://drop.example");
    let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
    let content = PayloadContent {
        message_type: MessageType::Text,
        msg_id: linkdrop_protocol::generate_message_id(),
        created_at: 1,
        seq: 0,
        text: Some("hello v2".to_string()),
        ack: None,
        missing: None,
        resend_of: None,
        receive: None,
        rescue: None,
    };
    let sealed = seal(
        &signing_key,
        &capability.capability.recipient_key,
        &capability.capability.drop_id,
        &content,
    )
    .unwrap();
    (
        capability.capability.drop_id,
        serde_json::to_string(&sealed.envelope).unwrap(),
    )
}

#[tokio::test]
async fn v2_envelope_is_stored_and_malformed_versions_are_rejected() -> Result<()> {
    let temp = TempDir::new()?;
    let (server, handle) = spawn_test_server(temp.path().join("server.db"), 16 * 1024).await?;
    let client = reqwest::Client::new();
    let (drop_id, body) = sample_v2_envelope();

    let created = client
        .put(format!("{server}/drop/{drop_id}"))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await?;
    let fetched = client
        .get(format!("{server}/drop/{drop_id}"))
        .send()
        .await?;
    let wrong_version = client
        .put(format!("{server}/drop/{}", generate_drop_id()))
        .header("content-type", "application/json")
        .body(body.replace("\"v\":2", "\"v\":3"))
        .send()
        .await?;
    let missing_nonce = client
        .put(format!("{server}/drop/{}", generate_drop_id()))
        .header("content-type", "application/json")
        .body(body.replace("\"nonce\"", "\"nonsense\""))
        .send()
        .await?;

    handle.abort();
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(fetched.status(), StatusCode::OK);
    assert_eq!(fetched.text().await?, body);
    assert_eq!(wrong_version.status(), StatusCode::BAD_REQUEST);
    assert_eq!(missing_nonce.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn long_poll_returns_when_drop_is_written_and_404_on_timeout() -> Result<()> {
    let temp = TempDir::new()?;
    let (server, handle) = linkdrop_server::spawn_test_server_with(
        temp.path().join("server.db"),
        linkdrop_server::ServerOptions {
            max_body_size: 16 * 1024,
            max_wait_seconds: 5,
        },
    )
    .await?;
    let client = reqwest::Client::new();
    let (drop_id, body) = sample_v2_envelope();

    let started = std::time::Instant::now();
    let timed_out = client
        .head(format!("{server}/drop/{}?wait=1", generate_drop_id()))
        .send()
        .await?;
    assert_eq!(timed_out.status(), StatusCode::NOT_FOUND);
    assert!(started.elapsed() >= std::time::Duration::from_millis(900));

    let waiter = {
        let client = client.clone();
        let url = format!("{server}/drop/{drop_id}?wait=5");
        tokio::spawn(async move { client.get(url).send().await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let put = client
        .put(format!("{server}/drop/{drop_id}"))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await?;
    let woken = waiter.await??;

    handle.abort();
    assert_eq!(put.status(), StatusCode::CREATED);
    assert_eq!(woken.status(), StatusCode::OK);
    assert_eq!(woken.text().await?, body);
    Ok(())
}

#[tokio::test]
async fn periodic_cleanup_deletes_expired_drops_while_running() -> Result<()> {
    let temp = TempDir::new()?;
    let database = temp.path().join("server.db");
    linkdrop_server::initialize_database(&database)?;
    {
        let conn = rusqlite::Connection::open(&database)?;
        conn.execute(
            "INSERT INTO drops (drop_id, body, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params!["old", b"{}".to_vec(), 1_i64],
        )?;
        conn.execute(
            "INSERT INTO drops (drop_id, body, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params!["fresh", b"{}".to_vec(), linkdrop_protocol::now_timestamp()],
        )?;
    }

    let cleanup = linkdrop_server::spawn_periodic_cleanup(database.clone(), 60, 1)
        .expect("interval above zero spawns cleanup");
    let mut remaining = 2;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let conn = rusqlite::Connection::open(&database)?;
        remaining = conn.query_row("SELECT COUNT(*) FROM drops", [], |row| row.get::<_, i64>(0))?;
        if remaining == 1 {
            break;
        }
    }
    cleanup.abort();
    assert_eq!(
        remaining, 1,
        "expired drop should be deleted by the periodic task"
    );
    Ok(())
}
