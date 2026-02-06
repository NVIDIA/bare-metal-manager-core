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
use reqwest::Client;
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
    /// It provides no guarantee that the checksum matches other than on the initial download.
    pub fn available(&self, filename: &Path, url: &str, checksum: &str) -> bool {
        self.available_actual(filename, url, checksum, None)
    }

    // Actual implementation, made visible to unit tests only
    fn available_actual(
        &self,
        filename: &Path,
        url: &str,
        checksum: &str,
        fake_sleep: Option<Duration>,
    ) -> bool {
        if filename.exists() {
            return true;
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
        if filename.exists() {
            return true;
        }

        state.downloading.insert(filename_string.clone());
        if state.client.is_none() {
            state.client = Some(Client::new());
        }

        let filename = filename.to_path_buf();
        let url = url.to_owned();
        let client = state.client.clone().unwrap();
        let actual = self.actual.clone();
        let checksum = checksum.to_owned();
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
                    if let Err(e) = verify_checksum(&dst_filename, &checksum) {
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

async fn download(
    filename: &Path,
    url: &String,
    dst_filename: &String,
    client: Client,
    fake_sleep: Option<Duration>,
) -> Result<(), Report> {
    // Actual downloader.  We aren't able to return errors to callers here, we just print to the log, and will retry on the next request.
    let dirname = match Path::parent(filename) {
        Some(x) => x.to_string_lossy().to_string(),
        None => {
            return Err(eyre!(
                "Could not find dirname of {}",
                filename.to_string_lossy()
            ));
        }
    };

    let _ = std::fs::create_dir_all(dirname);
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

/// verify_checks checks if the given filename uses the given checksum.  This is not meant to be security,
/// it's to check against download corruption or retrieving the wrong thing (such as if the vendor changed the URL).
/// We expect the hardware vendor to have done their own signing to ensure that firmware is not compromised.
fn verify_checksum(filename: &String, checksum: &String) -> Result<(), Report> {
    if checksum.is_empty() {
        // No validation requested
        return Ok(());
    }
    // md5 doesn't support async, must use the standard
    let mut file = std::fs::File::open(filename)?;

    let mut context = md5::Context::new();
    std::io::copy(&mut file, &mut context)?;

    let checksum_actual = format!("{:x}", context.compute());

    if &checksum_actual != checksum {
        return Err(eyre!(
            "Checksum mismatch: Expected {checksum} downloaded {checksum_actual}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn test_firmware_downloader_repeated() {
        // Check that if we get a bunch of parallel requests, only one actually downloads
        let filename = Path::new("/tmp/test_firmware_repeated");
        let url = "file:///dev/null".to_string();
        let _ = std::fs::remove_file(filename);
        let downloader = FirmwareDownloader::new();

        for _ in 0..9 {
            if downloader.available_actual(
                filename,
                &url,
                "",
                Some(std::time::Duration::from_secs(1)),
            ) {
                panic!("Should not have had something");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if !downloader.available_actual(filename, &url, "", Some(std::time::Duration::from_secs(1)))
        {
            panic!("Should have succeeded");
        }
        let _ = std::fs::remove_file(filename);
    }

    #[tokio::test]
    async fn test_checksum() -> Result<(), std::io::Error> {
        // Test that the checksum validation works
        let filename = Path::new("/tmp/test_firmware_checksum");
        let url = "file://tmp/test_firmware_checksum_src".to_string();

        let mut srcfile = File::create("/tmp/test_firmware_checksum_src").await?;
        for i in 0..2000 {
            srcfile.write_all(format!("{i}").as_bytes()).await?;
        }

        let _ = std::fs::remove_file(filename);
        let downloader = FirmwareDownloader::new();

        let mut count = 0;
        loop {
            if !downloader.available(filename, &url, "a08232ef8a758330f8698442550157f7") {
                tokio::time::sleep(Duration::from_millis(10)).await;
                count += 1;
                if count >= 1000 {
                    panic!("Should not have taken this long");
                }
            } else {
                let _ = std::fs::remove_file(filename);
                let _ = std::fs::remove_file("/tmp/test_Firmware_checksum_src");
                return Ok(());
            }
        }
    }
}
