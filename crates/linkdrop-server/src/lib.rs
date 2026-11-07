use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    body::Bytes,
    extract::{Path as AxumPath, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::put,
};
use clap::Parser;
use linkdrop_protocol::{MessageEnvelope, now_timestamp, v2};
use rusqlite::{Connection, Error as SqliteError, OptionalExtension, params};
use serde::Deserialize;
use tokio::sync::broadcast;

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
    /// How often expired drops are deleted while the server runs (0 disables periodic cleanup).
    #[arg(long, default_value_t = 5 * 60)]
    pub cleanup_interval_seconds: u64,
    /// Longest `?wait=` a GET or HEAD may hold a request open (0 disables the extension).
    #[arg(long, default_value_t = 30)]
    pub max_wait_seconds: u64,
}

/// Options for an in-process server.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub max_body_size: usize,
    pub max_wait_seconds: u64,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            max_body_size: 16 * 1024,
            max_wait_seconds: 30,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    database: PathBuf,
    max_body_size: usize,
    max_wait_seconds: u64,
    written: broadcast::Sender<String>,
}

impl AppState {
    pub fn new(database: PathBuf, max_body_size: usize) -> Self {
        Self::with_options(
            database,
            ServerOptions {
                max_body_size,
                ..ServerOptions::default()
            },
        )
    }

    pub fn with_options(database: PathBuf, options: ServerOptions) -> Self {
        let (written, _) = broadcast::channel(1024);
        Self {
            database,
            max_body_size: options.max_body_size,
            max_wait_seconds: options.max_wait_seconds,
            written,
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
    let cleanup = spawn_periodic_cleanup(
        args.database.clone(),
        args.ttl_seconds,
        args.cleanup_interval_seconds,
    );

    let app = build_app(AppState::with_options(
        args.database,
        ServerOptions {
            max_body_size: args.max_body_size,
            max_wait_seconds: args.max_wait_seconds,
        },
    ));
    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("failed to bind {}", args.bind))?;
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server exited unexpectedly");
    if let Some(cleanup) = cleanup {
        cleanup.abort();
    }
    served
}

/// Delete expired drops every `interval_seconds` while the server runs (spec V2 §6.5).
pub fn spawn_periodic_cleanup(
    database: PathBuf,
    ttl_seconds: u64,
    interval_seconds: u64,
) -> Option<tokio::task::JoinHandle<()>> {
    if interval_seconds == 0 {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let path = database.clone();
            let _ = tokio::task::spawn_blocking(move || cleanup_expired(&path, ttl_seconds)).await;
        }
    }))
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

/// Validate the envelope shape for every supported wire version without reinterpreting one as
/// another.
fn envelope_is_valid(body: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct VersionOnly {
        v: u8,
    }
    match serde_json::from_slice::<VersionOnly>(body) {
        Ok(VersionOnly { v: 1 }) => serde_json::from_slice::<MessageEnvelope>(body)
            .is_ok_and(|envelope| envelope.validate(true).is_ok()),
        Ok(VersionOnly { v: 2 }) => serde_json::from_slice::<v2::Envelope>(body)
            .is_ok_and(|envelope| envelope.validate().is_ok()),
        _ => false,
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
    if !envelope_is_valid(&body) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match insert_drop(&state.database, &drop_id, &body) {
        Ok(()) => {
            let _ = state.written.send(drop_id);
            StatusCode::CREATED.into_response()
        }
        Err(error) if is_unique_violation(&error) => StatusCode::CONFLICT.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Debug, Default, Deserialize)]
struct WaitQuery {
    #[serde(default)]
    wait: Option<u64>,
}

/// Optional long-poll extension (spec V2 §8.1): hold the request until the drop exists or the
/// wait elapses, then answer exactly as an immediate request would.
async fn wait_for_drop(state: &AppState, drop_id: &str, wait: Option<u64>) {
    let Some(seconds) = wait else {
        return;
    };
    let seconds = seconds.min(state.max_wait_seconds);
    if seconds == 0 {
        return;
    }
    let mut receiver = state.written.subscribe();
    if drop_exists(&state.database, drop_id).unwrap_or(true) {
        return;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        match tokio::time::timeout_at(deadline, receiver.recv()).await {
            Ok(Ok(written)) if written == drop_id => return,
            Ok(Ok(_)) => continue,
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => {
                if drop_exists(&state.database, drop_id).unwrap_or(true) {
                    return;
                }
            }
            Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => return,
        }
    }
}

async fn get_drop(
    State(state): State<Arc<AppState>>,
    AxumPath(drop_id): AxumPath<String>,
    Query(query): Query<WaitQuery>,
) -> Response {
    wait_for_drop(&state, &drop_id, query.wait).await;
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
    Query(query): Query<WaitQuery>,
) -> Response {
    wait_for_drop(&state, &drop_id, query.wait).await;
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
    spawn_test_server_with(
        database,
        ServerOptions {
            max_body_size,
            ..ServerOptions::default()
        },
    )
    .await
}

pub async fn spawn_test_server_with(
    database: PathBuf,
    options: ServerOptions,
) -> Result<(String, tokio::task::JoinHandle<()>)> {
    initialize_database(&database)?;
    let app = build_app(AppState::with_options(database, options));
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
