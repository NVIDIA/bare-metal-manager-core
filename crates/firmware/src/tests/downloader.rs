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
