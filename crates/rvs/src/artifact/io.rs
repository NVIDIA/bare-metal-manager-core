use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tower_http::services::ServeDir;

use crate::client::RackFirmwareData;
use crate::ctx::RvsCtx;
use crate::error::RvsError;
use crate::rack::Racks;
use crate::scenario;

/// A resolved artifact ready to be downloaded.
#[allow(dead_code)]
#[derive(Debug)]
pub struct ArtifactDownload {
    /// Destination path under cache_dir/<model>/<sot_release>/.
    pub output_path: String,
    /// Source URL to download from.
    pub url: String,
}

/// Download and cache all artifacts required for validation.
///
/// Covers the OS image, direct-URI artifacts, and SOT-resolved artifacts
/// defined in the matched scenarios. Does not touch the cache server --
/// call `start_cache_server` once before the main loop.
pub async fn process_artifacts(racks: &Racks, ctx: &RvsCtx) -> Result<(), RvsError> {
    let sot = fetch_sot(racks, ctx).await?;
    let downloads = scenario::resolve_artifact_urls(&sot, ctx)?;
    download_artifacts(downloads, ctx).await?;
    Ok(())
}

/// Start the HTTP artifact cache server.
///
/// Binds once and serves `cache_dir` for the lifetime of the process.
/// New files written by `process_artifacts` become visible immediately
/// without a restart. Call this once before the main validation loop.
pub async fn start_cache_server(ctx: &RvsCtx) -> Result<(), RvsError> {
    spawn_cache_server(ctx).await
}

/// Fetch the SOT JSON for the scenarios loaded in ctx.
///
/// Uses `ctx.sot_override_path` when set (test binary only), otherwise
/// lists all firmware records from NICC and returns the one whose `Name`
/// field matches the scenario's `sot_release`.
///
/// TODO[#416]: currently matches on the first scenario's `sot_release`
/// only. When multiple scenarios target different releases, this needs
/// to fetch one SOT per distinct release and route per-scenario.
async fn fetch_sot(_racks: &Racks, ctx: &RvsCtx) -> Result<RackFirmwareData, RvsError> {
    if let Some(path) = &ctx.sot_override_path {
        tracing::info!(path, "artifact: loading SOT from file override");
        let content = std::fs::read_to_string(path)
            .map_err(|e| RvsError::InvalidArg(format!("failed to read SOT override: {e}")))?;
        let config = serde_json::from_str(&content)
            .map_err(|e| RvsError::InvalidArg(format!("invalid SOT JSON: {e}")))?;
        return Ok(RackFirmwareData {
            id: "override".to_string(),
            config,
        });
    }

    let sot_release = ctx
        .scenarios
        .first()
        .map(|s| s.rack.sot_release.as_str())
        .ok_or_else(|| RvsError::InvalidArg("fetch_sot: no scenarios loaded".to_string()))?;

    tracing::info!(sot_release, "artifact: fetching SOT from NICC");

    let records = ctx.nicc.list_rack_firmware().await?;
    records
        .into_iter()
        .find(|r| r.config.get("Name").and_then(|v| v.as_str()) == Some(sot_release))
        .ok_or_else(|| {
            RvsError::InvalidArg(format!(
                "fetch_sot: no SOT record found for release '{sot_release}'"
            ))
        })
}

/// Download resolved artifacts into cache_dir/<model>/<sot_release>/.
///
/// Skips files already present on disk (cache hit). Respects
/// `max_concurrent_downloads` and `download_timeout_secs` from config.
async fn download_artifacts(
    artifacts: Vec<ArtifactDownload>,
    ctx: &RvsCtx,
) -> Result<(), RvsError> {
    let cfg = &ctx.cfg.artifact_cache;
    let client = reqwest::Client::new();
    let sem = Arc::new(Semaphore::new(cfg.max_concurrent_downloads as usize));
    let timeout = Duration::from_secs(cfg.download_timeout_secs);
    let mut set = JoinSet::new();

    for artifact in artifacts {
        let client = client.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            tokio::time::timeout(timeout, download_one(&client, &artifact))
                .await
                .map_err(|_| RvsError::Timeout(format!("download timed out: {}", artifact.url)))?
        });
    }

    while let Some(res) = set.join_next().await {
        res.map_err(|e| RvsError::InvalidArg(format!("download task panicked: {e}")))??;
    }
    Ok(())
}

/// Download a single artifact to `artifact.output_path`.
///
/// Creates parent directories as needed. Skips download if the file already
/// exists (cache hit). Streams the response body directly to disk.
async fn download_one(
    client: &reqwest::Client,
    artifact: &ArtifactDownload,
) -> Result<(), RvsError> {
    let path = std::path::Path::new(&artifact.output_path);

    // Cache hit: trust that a non-tmp file at `path` is complete, because we
    // only rename into place after a fully streamed body (and checksum, when
    // advertised) succeeds. We do NOT re-verify on hit -- a stable URL is
    // assumed to map to stable bytes for the lifetime of the cache.
    if path.exists() {
        tracing::debug!(path = artifact.output_path, "artifact: cache hit, skipping");
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    tracing::info!(
        url = artifact.url,
        path = artifact.output_path,
        "artifact: downloading"
    );

    let response =
        client.get(&artifact.url).send().await.map_err(|e| {
            RvsError::InvalidArg(format!("download failed for {}: {e}", artifact.url))
        })?;

    if !response.status().is_success() {
        return Err(RvsError::InvalidArg(format!(
            "download {}: HTTP {}",
            artifact.url,
            response.status()
        )));
    }

    let expected_sha256 = response
        .headers()
        .get("x-checksum-sha256")
        .and_then(|v| v.to_str().ok())
        .map(str::to_lowercase);

    // Stream to a sibling `.partial` file and rename on success, so an
    // interrupted download never poisons the cache with a truncated file.
    // Append (not `with_extension`) so `foo.bin` and `foo.json` get distinct
    // tmp paths instead of colliding on `foo.partial`.
    let tmp_path = std::path::PathBuf::from(format!("{}.partial", artifact.output_path));
    let mut file = tokio::fs::File::create(&tmp_path).await?;
    let mut hasher = Sha256::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| RvsError::InvalidArg(format!("stream error for {}: {e}", artifact.url)))?;
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.flush().await?;

    if let Some(expected) = expected_sha256 {
        let actual = hex::encode(hasher.finalize());
        if actual != expected {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(RvsError::ChecksumMismatch {
                path: artifact.output_path.clone(),
                expected,
                actual,
            });
        }
        tracing::info!(path = artifact.output_path, "artifact: checksum OK");
    }

    tokio::fs::rename(&tmp_path, path).await?;
    Ok(())
}

/// Spawn an HTTP file server that serves the artifact cache directory.
///
/// Runs in the background via `tokio::spawn`. Nodes pull artifacts from
/// this server (http://<host>:<serve_port>/<model>/<sot_release>/<file>)
/// during validation setup.
async fn spawn_cache_server(ctx: &RvsCtx) -> Result<(), RvsError> {
    let cache_dir = ctx.cfg.artifact_cache.cache_dir.clone();
    let port = ctx.cfg.artifact_cache.serve_port;
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(RvsError::Io)?;

    tracing::info!(port, cache_dir, "artifact: cache server listening");

    // TODO[#416]: ServeDir returns 404 on directory paths -- add an explicit
    // listing endpoint (e.g. GET /<model>/<sot_release>/) if nodes or operators
    // need to discover available artifacts without knowing filenames in advance.
    let app = Router::new().fallback_service(ServeDir::new(&cache_dir));

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "artifact: cache server error");
        }
    });

    Ok(())
}
