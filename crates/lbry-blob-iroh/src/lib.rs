//! Iroh transport for LBRY blob Have / Get / Put.
//!
//! ALPN: `lbry-blob-iroh/1`

mod protocol;
mod ticket;

pub use protocol::{
    client_get_blob, client_have, client_put_blob, serve_one, BlobStore, ALPN, MAX_BLOB_BYTES,
};
pub use ticket::{decode_ticket, encode_ticket};

use anyhow::{anyhow, Result};
use iroh::{Endpoint, EndpointAddr, endpoint::presets};
use lbry_blob::{load_blob_file, store_blob_file, verify_blob_hash};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info};

/// Connect to a superpeer ticket with the blob ALPN.
pub async fn connect_ticket(ticket: &str) -> Result<(Endpoint, iroh::endpoint::Connection)> {
    let addr: EndpointAddr = decode_ticket(ticket)?;
    let endpoint = Endpoint::bind(presets::N0)
        .await
        .map_err(|e| anyhow!("client bind: {e}"))?;
    let conn = endpoint
        .connect(addr, ALPN)
        .await
        .map_err(|e| anyhow!("connect: {e}"))?;
    Ok((endpoint, conn))
}

/// Filesystem-backed blob store for superpeers.
#[derive(Clone)]
pub struct FsBlobStore {
    dir: Arc<PathBuf>,
}

impl FsBlobStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: Arc::new(dir.into()),
        }
    }

    pub fn dir(&self) -> &Path {
        self.dir.as_path()
    }
}

impl BlobStore for FsBlobStore {
    fn load(&self, hash_hex: &str) -> Result<Option<Vec<u8>>> {
        match load_blob_file(self.dir.as_path(), hash_hex) {
            Ok(data) => Ok(Some(data)),
            Err(_) => {
                let p = self.dir.join(hash_hex.to_lowercase());
                if p.exists() {
                    Ok(Some(std::fs::read(p)?))
                } else if self.dir.join(hash_hex).exists() {
                    Ok(Some(std::fs::read(self.dir.join(hash_hex))?))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn store(&self, hash_hex: &str, data: &[u8]) -> Result<()> {
        store_blob_file(self.dir.as_path(), hash_hex, data)
    }
}

/// Run accept loop for a superpeer (download + upload).
pub async fn run_superpeer(store: FsBlobStore) -> Result<Endpoint> {
    let endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| anyhow!("endpoint bind: {e}"))?;

    endpoint.online().await;

    let ep = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let store = store.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_incoming(incoming, store).await {
                    error!("connection error: {e:#}");
                }
            });
        }
    });

    Ok(endpoint)
}

async fn handle_incoming(
    incoming: iroh::endpoint::Incoming,
    store: FsBlobStore,
) -> Result<()> {
    let conn = incoming.await.map_err(|e| anyhow!("accept: {e}"))?;
    let remote = conn.remote_id();
    info!("accepted connection from {remote}");
    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let store = store.clone();
                if let Err(e) = serve_one(&mut send, &mut recv, &store).await {
                    error!("request error: {e:#}");
                }
            }
            Err(e) => {
                info!("connection closed ({remote}): {e}");
                break;
            }
        }
    }
    Ok(())
}

/// Upload every blob file in a directory (skips DEMO.json).
pub async fn upload_dir(conn: &iroh::endpoint::Connection, dir: &Path) -> Result<usize> {
    let mut n = 0usize;
    let mut hashes = lbry_blob::list_blob_hashes_in_dir(dir)?;
    // Prefer uploading content blobs before sd is fine either way; any order works.
    for hash in hashes.drain(..) {
        let data = load_blob_file(dir, &hash)?;
        verify_blob_hash(&data, &hash)?;
        client_put_blob(conn, &hash, &data).await?;
        n += 1;
        info!("uploaded {hash}");
    }
    Ok(n)
}
