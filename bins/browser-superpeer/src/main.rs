//! browser-superpeer: LBRY blob download/upload superpeer + localhost companion over Iroh.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::{Multipart, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use lbry_blob::{
    decrypt_content_blob, pack_file, parse_sd_blob, verify_blob_hash,
};
use lbry_blob_iroh::{
    client_get_blob, client_have, connect_ticket, encode_ticket, run_superpeer, upload_dir,
    FsBlobStore,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(
    name = "browser-superpeer",
    about = "LBRY blob superpeer (download + upload) and browser companion over Iroh"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Pack a file into LBRY-shaped encrypted blobs + sd.
    Pack {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = "fixtures/demo")]
        out: PathBuf,
    },
    /// Serve blobs (Get + Put). Download peer that also accepts peer uploads.
    Superpeer {
        #[arg(long, default_value = "fixtures/demo")]
        blobs: PathBuf,
    },
    /// Fetch and assemble a stream over Iroh.
    Fetch {
        #[arg(long)]
        ticket: String,
        #[arg(long)]
        sd_hash: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long, default_value = "assembled.bin")]
        out: PathBuf,
    },
    /// Upload a local blob directory to a superpeer (CLI first path).
    Upload {
        #[arg(long)]
        ticket: String,
        /// Directory of blob files named by SHA-384 hex (and optional DEMO.json).
        #[arg(long)]
        blobs: PathBuf,
    },
    /// Localhost companion: HTTP API + web UI (play + upload).
    Companion {
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
        #[arg(long, default_value = "web")]
        web: PathBuf,
        /// Temp dir for uploads / assembled media.
        #[arg(long, default_value = "cache")]
        cache: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Pack { input, out } => {
            let p = pack_file(&input, &out)?;
            println!("Packed OK");
            println!("  blob_dir   = {}", p.blob_dir.display());
            println!("  sd_hash    = {}", p.sd_hash);
            println!("  stream_key = {}", p.stream_key_hex);
            println!("  filename   = {}", p.filename);
            Ok(())
        }
        Cmd::Superpeer { blobs } => cmd_superpeer(blobs).await,
        Cmd::Fetch {
            ticket,
            sd_hash,
            key,
            out,
        } => cmd_fetch(ticket, sd_hash, key, out).await,
        Cmd::Upload { ticket, blobs } => cmd_upload(ticket, blobs).await,
        Cmd::Companion {
            listen,
            web,
            cache,
        } => cmd_companion(listen, web, cache).await,
    }
}

async fn cmd_superpeer(blobs: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&blobs)?;
    let blobs = blobs.canonicalize().context("canonicalize blobs dir")?;
    let store = FsBlobStore::new(blobs.clone());
    let endpoint = run_superpeer(store).await?;
    let addr = endpoint.addr();
    let t = encode_ticket(&addr)?;
    println!("========================================");
    println!("LBRY superpeer (download + upload over Iroh)");
    println!("  blobs       = {}", blobs.display());
    println!("  endpoint_id = {}", addr.id);
    println!("  ticket      = {t}");
    println!("========================================");
    println!("Peers may GetBlob and PutBlob (hash-verified store).");
    println!("Ctrl+C to stop.");
    tokio::signal::ctrl_c().await.ok();
    info!("shutting down");
    endpoint.close().await;
    Ok(())
}

async fn cmd_fetch(
    ticket: String,
    sd_hash: String,
    key_override: Option<String>,
    out: PathBuf,
) -> Result<()> {
    let (endpoint, conn) = connect_ticket(&ticket).await?;
    info!("connected; fetching sd_hash={sd_hash}");
    let sd_raw = client_get_blob(&conn, &sd_hash).await?;
    verify_blob_hash(&sd_raw, &sd_hash)?;
    let mut sd = parse_sd_blob(&sd_raw)?;
    if let Some(k) = key_override {
        sd.key = k;
    }
    let mut out_bytes = Vec::new();
    for entry in &sd.blobs {
        let raw = client_get_blob(&conn, &entry.blob_hash).await?;
        verify_blob_hash(&raw, &entry.blob_hash)?;
        let plain = decrypt_content_blob(&raw, &sd.key, &entry.iv)?;
        out_bytes.extend_from_slice(&plain);
        info!(
            "blob {} ok ({} ciphertext bytes)",
            &entry.blob_hash[..16.min(entry.blob_hash.len())],
            raw.len()
        );
    }
    std::fs::write(&out, &out_bytes)?;
    println!(
        "Wrote {} bytes to {} ({} content blobs)",
        out_bytes.len(),
        out.display(),
        sd.blobs.len()
    );
    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    Ok(())
}

async fn cmd_upload(ticket: String, blobs: PathBuf) -> Result<()> {
    if !blobs.is_dir() {
        bail!("blobs path is not a directory: {}", blobs.display());
    }
    let (endpoint, conn) = connect_ticket(&ticket).await?;
    let n = upload_dir(&conn, &blobs).await?;
    println!("Uploaded {n} blob(s) to superpeer");
    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    Ok(())
}

// --- Companion ---

#[derive(Clone)]
struct AppState {
    lock: Arc<Mutex<()>>,
    cache: PathBuf,
}

#[derive(Deserialize)]
struct PlayBody {
    ticket: String,
    sd_hash: String,
    #[serde(default)]
    key: Option<String>,
}

#[derive(Serialize)]
struct PlayResponse {
    ok: bool,
    filename: String,
    bytes: usize,
    content_blobs: usize,
    media_path: String,
    message: String,
}

#[derive(Serialize)]
struct UploadResponse {
    ok: bool,
    blobs_uploaded: usize,
    sd_hash: Option<String>,
    message: String,
}

async fn cmd_companion(listen: SocketAddr, web: PathBuf, cache: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&cache)?;
    let state = AppState {
        lock: Arc::new(Mutex::new(())),
        cache: cache.clone(),
    };

    let app = Router::new()
        .route("/", get(index_page))
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/play", post(api_play))
        .route("/api/upload", post(api_upload))
        .route("/media/{name}", get(serve_media))
        .nest_service("/static", ServeDir::new(&web))
        .layer(CorsLayer::permissive())
        .with_state(state);

    println!("Companion listening on http://{listen}");
    println!("  Play:   paste superpeer ticket + sd_hash");
    println!("  Upload: paste ticket + choose a file (packed then PutBlob over Iroh)");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index_page() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn api_play(
    State(st): State<AppState>,
    Json(body): Json<PlayBody>,
) -> Result<Json<PlayResponse>, AppError> {
    let _g = st.lock.lock().await;
    let (endpoint, conn) = connect_ticket(&body.ticket)
        .await
        .map_err(AppError::from)?;
    let sd_raw = client_get_blob(&conn, &body.sd_hash)
        .await
        .map_err(AppError::from)?;
    verify_blob_hash(&sd_raw, &body.sd_hash).map_err(AppError::from)?;
    let mut sd = parse_sd_blob(&sd_raw).map_err(AppError::from)?;
    if let Some(k) = body.key.clone() {
        if !k.is_empty() {
            sd.key = k;
        }
    }
    let mut out_bytes = Vec::new();
    for entry in &sd.blobs {
        let raw = client_get_blob(&conn, &entry.blob_hash)
            .await
            .map_err(AppError::from)?;
        verify_blob_hash(&raw, &entry.blob_hash).map_err(AppError::from)?;
        let plain = decrypt_content_blob(&raw, &sd.key, &entry.iv).map_err(AppError::from)?;
        out_bytes.extend_from_slice(&plain);
    }
    let filename = {
        let raw = hex::decode(&sd.filename).unwrap_or_else(|_| b"assembled.bin".to_vec());
        String::from_utf8_lossy(&raw).to_string()
    };
    let safe_name = format!(
        "{}_{}",
        &body.sd_hash[..16.min(body.sd_hash.len())],
        filename.replace(['/', '\\'], "_")
    );
    let path = st.cache.join(&safe_name);
    std::fs::write(&path, &out_bytes).map_err(|e| AppError::from(anyhow!(e)))?;
    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    Ok(Json(PlayResponse {
        ok: true,
        filename,
        bytes: out_bytes.len(),
        content_blobs: sd.blobs.len(),
        media_path: format!("/media/{safe_name}"),
        message: format!(
            "Verified {} LBRY-shaped blobs over Iroh.",
            sd.blobs.len()
        ),
    }))
}

/// Web upload: multipart fields `ticket` + `file`.
/// Companion packs the file locally, then PutBlob each piece to the superpeer.
async fn api_upload(
    State(st): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, AppError> {
    let _g = st.lock.lock().await;
    let mut ticket = String::new();
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut filename = "upload.bin".to_string();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::from(anyhow!("multipart: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        if name == "ticket" {
            ticket = field
                .text()
                .await
                .map_err(|e| AppError::from(anyhow!("ticket field: {e}")))?;
        } else if name == "file" {
            if let Some(fnm) = field.file_name().map(|s| s.to_string()) {
                filename = fnm;
            }
            file_bytes = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| AppError::from(anyhow!("file field: {e}")))?
                    .to_vec(),
            );
        }
    }

    if ticket.trim().is_empty() {
        return Err(AppError::from(anyhow!("ticket required")));
    }
    let data = file_bytes.ok_or_else(|| AppError::from(anyhow!("file required")))?;
    if data.is_empty() {
        return Err(AppError::from(anyhow!("empty file")));
    }

    // Stage raw file + pack into cache/upload-<ts>/
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let work = st.cache.join(format!("upload-{stamp}"));
    std::fs::create_dir_all(&work).map_err(|e| AppError::from(anyhow!(e)))?;
    let src = work.join(&filename);
    std::fs::write(&src, &data).map_err(|e| AppError::from(anyhow!(e)))?;
    let pack_dir = work.join("blobs");
    let packed = pack_file(&src, &pack_dir).map_err(AppError::from)?;

    let (endpoint, conn) = connect_ticket(ticket.trim())
        .await
        .map_err(AppError::from)?;
    let n = upload_dir(&conn, &pack_dir)
        .await
        .map_err(AppError::from)?;
    conn.close(0u32.into(), b"done");
    endpoint.close().await;

    Ok(Json(UploadResponse {
        ok: true,
        blobs_uploaded: n,
        sd_hash: Some(packed.sd_hash.clone()),
        message: format!(
            "Packed '{}' and uploaded {n} blob(s). sd_hash={} — any peer can now GetBlob this stream from the superpeer.",
            packed.filename, packed.sd_hash
        ),
    }))
}

async fn serve_media(
    State(st): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Response, AppError> {
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(AppError::from(anyhow!("bad name")));
    }
    let path = st.cache.join(&name);
    let data = std::fs::read(&path).map_err(|e| AppError::from(anyhow!("media: {e}")))?;
    let ctype = if name.ends_with(".wav") {
        "audio/wav"
    } else if name.ends_with(".mp4") {
        "video/mp4"
    } else if name.ends_with(".webm") {
        "video/webm"
    } else if name.ends_with(".mp3") {
        "audio/mpeg"
    } else {
        "application/octet-stream"
    };
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, ctype)],
        data,
    )
        .into_response())
}

struct AppError(anyhow::Error);
impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        Self(e)
    }
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!("api error: {:#}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{:#}", self.0) })),
        )
            .into_response()
    }
}

// silence unused import in some builds
#[allow(dead_code)]
async fn _have(ticket: &str, hash: &str) -> Result<bool> {
    let (ep, conn) = connect_ticket(ticket).await?;
    let h = client_have(&conn, hash).await?;
    conn.close(0u32.into(), b"x");
    ep.close().await;
    Ok(h)
}
