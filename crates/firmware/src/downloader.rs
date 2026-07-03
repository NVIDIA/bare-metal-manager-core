/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Coordinates downloading firmware in the background with multiple possible requestors

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eyre::{Report, WrapErr, eyre};
use futures_util::StreamExt;
use reqwest_middleware::ClientWithMiddleware as Client;
use sha2::{Digest, Sha256};
use tokio::fs::File;

#[derive(Clone, Debug)]
pub struct FirmwareDownloader {
    // Actual structure wrapped in an Arc so that we can clone the FirmwareDownloader and have the clones all point to one instance.
    actual: Arc<Mutex<FirmwareDownloaderActual>>,
}

#[derive(Debug)]
struct FirmwareDownloaderActual {
    downloading: HashSet<String>,
    client: Option<Client>,
}

impl Default for FirmwareDownloader {
    fn default() -> Self {
        Self::new()
    }
}

impl FirmwareDownloader {
    pub fn new() -> FirmwareDownloader {
        FirmwareDownloader {
            actual: Arc::new(Mutex::new(FirmwareDownloaderActual {
                downloading: HashSet::new(),
                client: None, // Not created until we actually need it
            })),
        }
    }

    /// available will return true if the given file is present, otherwise it will return false after starting a download in the background.
    /// Anything trying to check the same file while it is downloading will get the exact same result, but will not start a new download.
    /// It verifies the downloaded file against sha256 when a checksum is provided.
    pub fn available(&self, filename: &Path, url: &str, sha256: &str) -> bool {
        self.available_actual(filename, url, sha256, None)
    }

    // Implementation behind available(). Tests call this directly to control async timing.
    pub(crate) fn available_actual(
        &self,
        filename: &Path,
        url: &str,
        sha256: &str,
        fake_sleep: Option<Duration>,
    ) -> bool {
        match cached_file_status(filename, sha256) {
            CachedFileStatus::Available => return true,
            CachedFileStatus::NeedsDownload => {}
            CachedFileStatus::Unusable => return false,
        }

        if url.is_empty() {
            tracing::error!("Firmware with file not present has no URL: {filename:?}");
            return false;
        }

        let filename_string = filename.to_str().unwrap().to_string();

        let mut state = self.actual.lock().unwrap();
        if state.downloading.contains(&filename_string) {
            // We are already downloading this
            return false;
        }

        // Slight timing hole, recheck for the file
        match cached_file_status(filename, sha256) {
            CachedFileStatus::Available => return true,
            CachedFileStatus::NeedsDownload => {}
            CachedFileStatus::Unusable => return false,
        }

        state.downloading.insert(filename_string.clone());
        if state.client.is_none() {
            // The `reqwest-tracing` middleware injects the current span's W3C trace context into
            // every outgoing request (#2438).
            state.client = Some(
                reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
                    .with(reqwest_tracing::TracingMiddleware::default())
                    .build(),
            );
        }

        let filename = filename.to_path_buf();
        let url = url.to_owned();
        let sha256 = sha256.to_owned();
        let client = state.client.clone().unwrap();
        let actual = self.actual.clone();
        tokio::spawn(async move {
            let dst_filename = format!("{filename_string}.download");
            match download(&filename, &url, &dst_filename, client, fake_sleep).await {
                Err(e) => {
                    tracing::error!("FirmwareDownloader failed: {e}");
                    let _ = std::fs::remove_file(dst_filename);
                    actual
                        .lock()
                        .unwrap()
                        .clear_download_state(&filename_string);
                }
                Ok(_) => {
                    tracing::info!("Completed download of {url} to {filename_string}");
                    if let Err(e) = verify_sha256(&dst_filename, &sha256) {
                        tracing::error!("FirmwareDownloader checksum for {url} failed: {e}");
                        let _ = std::fs::remove_file(dst_filename);
                        actual
                            .lock()
                            .unwrap()
                            .clear_download_state(&filename_string);
                        return;
                    }
                    if let Err(e) = std::fs::rename(&dst_filename, &filename) {
                        tracing::error!("FirmwareDownloader rename failed: {e}");
                        let _ = std::fs::remove_file(dst_filename);
                        actual
                            .lock()
                            .unwrap()
                            .clear_download_state(&filename_string);
                        return;
                    }

                    actual
                        .lock()
                        .unwrap()
                        .clear_download_state(&filename_string);
                }
            };
        });
        false
    }
}

impl FirmwareDownloaderActual {
    fn clear_download_state(&mut self, filename: &String) {
        self.downloading.remove(filename);
    }
}

enum CachedFileStatus {
    Available,
    NeedsDownload,
    Unusable,
}

fn cached_file_status(filename: &Path, sha256: &str) -> CachedFileStatus {
    let filename_str = filename.to_string_lossy();

    if !filename.exists() {
        return CachedFileStatus::NeedsDownload;
    }

    match verify_sha256(&filename_str, sha256) {
        Ok(()) => CachedFileStatus::Available,
        Err(err) => {
            tracing::warn!(
                "Cached firmware artifact {} failed checksum verification: {err}",
                filename.display()
            );

            if let Err(err) = std::fs::remove_file(filename) {
                tracing::error!(
                    "Failed to remove stale cached firmware artifact {}: {err}",
                    filename.display()
                );
                return CachedFileStatus::Unusable;
            }

            CachedFileStatus::NeedsDownload
        }
    }
}

async fn download(
    filename: &Path,
    url: &String,
    dst_filename: &String,
    client: Client,
    fake_sleep: Option<Duration>,
) -> Result<(), Report> {
    // Actual downloader.  We aren't able to return errors to callers here, we just print to the log, and will retry on the next request.
    let dirname = match Path::parent(filename) {
        Some(x) => x,
        None => {
            return Err(eyre!(
                "Could not find dirname of {}",
                filename.to_string_lossy()
            ));
        }
    };

    std::fs::create_dir_all(dirname)
        .wrap_err(format!("Unable to create directory {}", dirname.display()))?;
    let mut dst_file = File::create(&dst_filename)
        .await
        .wrap_err(format!("Unable to create file {dst_filename}"))?;

    if let Some(duration) = fake_sleep {
        // For testing only, wait a given amount of time then write an empty file
        tokio::time::sleep(duration).await;
        return Ok(());
    }

    if url.starts_with("file://") {
        // Just copies a local file, for testing
        let src_filename = url.strip_prefix("file:/").unwrap(); // Leave the second / for the root
        let mut src_file = File::open(src_filename)
            .await
            .wrap_err(format!("FirmwareDownloader could not open source {url}"))?;
        return tokio::io::copy(&mut src_file, &mut dst_file)
            .await
            .map(|_| ())
            .map_err(|e| eyre!("FirmwareDownloader had problems saving file from {url}: {e}"));
    }

    let res = client.get(url).send().await.wrap_err(format!(
        "FirmwareDownloader got error trying to download {url}"
    ))?;
    if !res.status().is_success() {
        return Err(eyre!(
            "FirmwareDownloader got non-success status trying to download {url}: {}",
            res.status()
        ));
    }
    let mut body = res.bytes_stream();
    while let Some(segment) = body.next().await {
        match segment {
            Err(e) => {
                return Err(eyre!(
                    "FirmwareDownloader had problems downloading {url}: {e}"
                ));
            }
            Ok(segment) => {
                tokio::io::copy(&mut segment.as_ref(), &mut dst_file)
                    .await
                    .wrap_err(format!(
                        "FirmwareDownloader had problems saving file from {url}"
                    ))?;
            }
        }
    }

    // Success
    Ok(())
}

/// Checks if the given filename uses the given checksum. This is not meant to be security,
/// it's to check against download corruption or retrieving the wrong thing (such as if the vendor changed the URL).
/// We expect the hardware vendor to have done their own signing to ensure that firmware is not compromised.
fn verify_sha256(filename: &str, checksum: &str) -> Result<(), Report> {
    let checksum = checksum.trim().to_ascii_lowercase();
    if checksum.is_empty() {
        return Ok(());
    }

    let mut file = std::fs::File::open(filename)?;

    let mut context = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }

    let checksum_actual = hex::encode(context.finalize());

    if checksum_actual != checksum {
        return Err(eyre!(
            "Checksum mismatch: Expected {checksum} downloaded {checksum_actual}"
        ));
    }
    Ok(())
}
