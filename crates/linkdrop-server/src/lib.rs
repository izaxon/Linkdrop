use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::put,
};
use clap::Parser;
use linkdrop_protocol::{MessageEnvelope, now_timestamp};
use rusqlite::{Connection, Error as SqliteError, OptionalExtension, params};

#[derive(Debug, Clone, Parser)]
pub struct ServerArgs {
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub bind: String,
    #[arg(long, default_value = "linkdrop-server.db")]
    pub database: PathBuf,
    #[arg(long, default_value_t = 16 * 1024)]
    pub max_body_size: usize,
    #[arg(long, default_value_t = 7 * 24 * 60 * 60)]
    pub ttl_seconds: u64,
}

#[derive(Clone)]
pub struct AppState {
    database: PathBuf,
    max_body_size: usize,
}

impl AppState {
    pub fn new(database: PathBuf, max_body_size: usize) -> Self {
        Self {
            database,
            max_body_size,
        }
    }
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route(
            "/drop/{drop_id}",
            put(put_drop).get(get_drop).head(head_drop),
        )
        .with_state(Arc::new(state))
}

pub async fn run(args: ServerArgs) -> Result<()> {
    initialize_database(&args.database)?;
    cleanup_expired(&args.database, args.ttl_seconds)?;

    let app = build_app(AppState::new(args.database, args.max_body_size));
    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("failed to bind {}", args.bind))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server exited unexpectedly")?;
    Ok(())
}

pub fn initialize_database(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create database directory {}", parent.display()))?;
    }
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open SQLite database {}", path.display()))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS drops (
            drop_id TEXT PRIMARY KEY,
            body BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_drops_created_at ON drops(created_at);",
    )
    .context("failed to initialize database schema")?;
    Ok(())
}

pub fn cleanup_expired(path: &Path, ttl_seconds: u64) -> Result<usize> {
    let cutoff = now_timestamp() - ttl_seconds as i64;
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open SQLite database {}", path.display()))?;
    let deleted = conn
        .execute("DELETE FROM drops WHERE created_at < ?1", params![cutoff])
        .context("failed to delete expired drops")?;
    Ok(deleted)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn put_drop(
    State(state): State<Arc<AppState>>,
    AxumPath(drop_id): AxumPath<String>,
    body: Bytes,
) -> Response {
    if body.len() > state.max_body_size {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }

    let envelope: MessageEnvelope = match serde_json::from_slice(&body) {
        Ok(envelope) => envelope,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if envelope.validate(true).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match insert_drop(&state.database, &drop_id, &body) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(error) if is_unique_violation(&error) => StatusCode::CONFLICT.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_drop(
    State(state): State<Arc<AppState>>,
    AxumPath(drop_id): AxumPath<String>,
) -> Response {
    match load_drop(&state.database, &drop_id) {
        Ok(Some(body)) => {
            let mut response = body.into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn head_drop(
    State(state): State<Arc<AppState>>,
    AxumPath(drop_id): AxumPath<String>,
) -> Response {
    match drop_exists(&state.database, &drop_id) {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn insert_drop(path: &Path, drop_id: &str, body: &[u8]) -> Result<()> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open SQLite database {}", path.display()))?;
    conn.execute(
        "INSERT INTO drops (drop_id, body, created_at) VALUES (?1, ?2, ?3)",
        params![drop_id, body, now_timestamp()],
    )
    .map(|_| ())
    .map_err(Into::into)
}

fn load_drop(path: &Path, drop_id: &str) -> Result<Option<Vec<u8>>> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open SQLite database {}", path.display()))?;
    conn.query_row(
        "SELECT body FROM drops WHERE drop_id = ?1",
        params![drop_id],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(Into::into)
}

fn drop_exists(path: &Path, drop_id: &str) -> Result<bool> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open SQLite database {}", path.display()))?;
    let found = conn
        .query_row(
            "SELECT 1 FROM drops WHERE drop_id = ?1",
            params![drop_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(found)
}

fn is_unique_violation(error: &anyhow::Error) -> bool {
    if let Some(SqliteError::SqliteFailure(code, _)) = error.downcast_ref::<SqliteError>() {
        return code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
            || code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE;
    }
    false
}

pub async fn spawn_test_server(
    database: PathBuf,
    max_body_size: usize,
) -> Result<(String, tokio::task::JoinHandle<()>)> {
    initialize_database(&database)?;
    let app = build_app(AppState::new(database, max_body_size));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind test listener")?;
    let address = listener
        .local_addr()
        .context("failed to read test address")?;
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                tokio::time::sleep(Duration::from_secs(600)).await;
            })
            .await
            .expect("test server should run");
    });
    Ok((format!("http://{}", address), handle))
}

pub fn require_contact_prekey(contact_prekey: Option<&str>) -> Result<&str> {
    contact_prekey
        .ok_or_else(|| anyhow!("contact does not have a prekey; import their contact bundle first"))
}
