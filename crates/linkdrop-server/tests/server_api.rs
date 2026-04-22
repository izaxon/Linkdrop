use anyhow::Result;
use linkdrop_protocol::{
    DecryptedPayload, DropRef, IdentityFile, encrypt_payload_for_contact, generate_drop_id,
};
use linkdrop_server::spawn_test_server;
use reqwest::StatusCode;
use tempfile::TempDir;

fn sample_envelope(server: &str) -> String {
    let identity = IdentityFile::generate("Alice");
    let payload = DecryptedPayload {
        text: "hello".to_string(),
        prev_msg_id: None,
    };
    let reply_drop = DropRef {
        server: server.to_string(),
        drop_id: generate_drop_id(),
    };
    let envelope = encrypt_payload_for_contact(
        &identity,
        &identity.tagged_prekey_public_key(),
        reply_drop,
        &payload,
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
