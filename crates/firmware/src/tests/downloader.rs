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

use std::path::Path;
use std::time::Duration;

use sha2::Digest;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::downloader::*;

#[tokio::test]
async fn test_firmware_downloader_repeated() {
    // Check that if we get a bunch of parallel requests, only one actually downloads
    let filename = Path::new("/tmp/test_firmware_repeated");
    let url = "file:///dev/null".to_string();
    let _ = std::fs::remove_file(filename);
    let downloader = FirmwareDownloader::new();

    for _ in 0..9 {
        if downloader.available_actual(filename, &url, "", Some(std::time::Duration::from_secs(1)))
        {
            panic!("Should not have had something");
        }
    }

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    if !downloader.available_actual(filename, &url, "", Some(std::time::Duration::from_secs(1))) {
        panic!("Should have succeeded");
    }
    let _ = std::fs::remove_file(filename);
}

#[tokio::test]
async fn test_download_without_checksum() -> Result<(), std::io::Error> {
    let filename = Path::new("/tmp/test_firmware_without_checksum");
    let src_filename = "/tmp/test_firmware_without_checksum_src";
    let url = format!("file://{src_filename}");

    let mut srcfile = File::create(src_filename).await?;
    for i in 0..2000 {
        srcfile.write_all(format!("{i}").as_bytes()).await?;
    }
    srcfile.flush().await?;

    let _ = std::fs::remove_file(filename);
    let downloader = FirmwareDownloader::new();

    let mut count = 0;
    loop {
        if !downloader.available(filename, &url, "") {
            tokio::time::sleep(Duration::from_millis(10)).await;
            count += 1;
            if count >= 1000 {
                panic!("Should not have taken this long");
            }
        } else {
            let _ = std::fs::remove_file(filename);
            let _ = std::fs::remove_file(src_filename);
            return Ok(());
        }
    }
}

#[tokio::test]
async fn test_available_verifies_sha256_checksum() -> Result<(), std::io::Error> {
    let filename = Path::new("/tmp/test_firmware_sha256_checksum");
    let src_filename = "/tmp/test_firmware_sha256_checksum_src";
    let url = format!("file://{src_filename}");
    let contents = b"firmware artifact";

    let mut srcfile = File::create(src_filename).await?;
    srcfile.write_all(contents).await?;
    srcfile.flush().await?;

    let _ = std::fs::remove_file(filename);
    let downloader = FirmwareDownloader::new();
    let checksum = format!(
        " {} ",
        hex::encode(sha2::Sha256::digest(contents)).to_ascii_uppercase()
    );

    let mut count = 0;
    loop {
        if !downloader.available(filename, &url, &checksum) {
            tokio::time::sleep(Duration::from_millis(10)).await;
            count += 1;
            if count >= 1000 {
                panic!("Should not have taken this long");
            }
        } else {
            let _ = std::fs::remove_file(filename);
            let _ = std::fs::remove_file(src_filename);
            return Ok(());
        }
    }
}

#[tokio::test]
async fn test_available_rejects_stale_cache_with_wrong_sha256() -> Result<(), std::io::Error> {
    let filename = Path::new("/tmp/test_firmware_stale_cache_wrong_checksum");
    let src_filename = "/tmp/test_firmware_stale_cache_wrong_checksum_src";
    let url = format!("file://{src_filename}");
    let contents = b"fresh firmware artifact";

    let mut cached_file = File::create(filename).await?;
    cached_file.write_all(b"stale firmware artifact").await?;
    cached_file.flush().await?;
    drop(cached_file);

    let mut srcfile = File::create(src_filename).await?;
    srcfile.write_all(contents).await?;
    srcfile.flush().await?;
    drop(srcfile);

    let downloader = FirmwareDownloader::new();
    let checksum = hex::encode(sha2::Sha256::digest(contents));

    assert!(!downloader.available(filename, &url, &checksum));

    let mut count = 0;
    loop {
        if !downloader.available(filename, &url, &checksum) {
            tokio::time::sleep(Duration::from_millis(10)).await;
            count += 1;
            if count >= 1000 {
                panic!("Should not have taken this long");
            }
        } else {
            assert_eq!(tokio::fs::read(filename).await?, contents);
            let _ = std::fs::remove_file(filename);
            let _ = std::fs::remove_file(src_filename);
            return Ok(());
        }
    }
}

#[tokio::test]
async fn test_available_checksum_failure_does_not_publish_file() -> Result<(), std::io::Error> {
    let filename = Path::new("/tmp/test_firmware_sha256_checksum_failure");
    let src_filename = "/tmp/test_firmware_sha256_checksum_failure_src";
    let url = format!("file://{src_filename}");

    let mut srcfile = File::create(src_filename).await?;
    srcfile.write_all(b"firmware artifact").await?;
    srcfile.flush().await?;

    let _ = std::fs::remove_file(filename);
    let downloader = FirmwareDownloader::new();

    assert!(!downloader.available(filename, &url, &"0".repeat(64)));
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(!filename.exists());
    let _ = std::fs::remove_file(src_filename);
    Ok(())
}
