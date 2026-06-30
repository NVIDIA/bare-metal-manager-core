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

use std::path::{Path, PathBuf};

use eyre::{Result, eyre};
use model::firmware::FirmwareEntry;

use crate::artifact_cache::firmware_cache_filename;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedFirmwareArtifact {
    pub local_path: PathBuf,
    pub source: ResolvedFirmwareArtifactSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedFirmwareArtifactSource {
    Remote { url: String, sha256: String },
    Local,
}

pub fn resolve_files_firmware_artifact(
    firmware_cache_directory: &Path,
    firmware: &FirmwareEntry,
    pos: u32,
) -> Result<Option<ResolvedFirmwareArtifact>> {
    if firmware.files.is_empty() {
        return Ok(None);
    }

    let index = usize::try_from(pos).unwrap_or(usize::MAX);
    let artifact = firmware.files.get(index).ok_or_else(|| {
        eyre!(
            "firmware version {} has no files[] artifact at index {}",
            firmware.version,
            pos
        )
    })?;

    let url = artifact
        .url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty());

    let filename = artifact
        .filename
        .as_deref()
        .map(str::trim)
        .filter(|filename| !filename.is_empty());

    let local_path = if let Some(url) = url {
        firmware_cache_filename(firmware_cache_directory, url).ok_or_else(|| {
            eyre!(
                "firmware version {} files[] artifact at index {} URL does not include a filename",
                firmware.version,
                pos
            )
        })?
    } else if let Some(filename) = filename {
        PathBuf::from(filename)
    } else {
        return Err(eyre!(
            "firmware version {} files[] artifact at index {} has no filename or URL",
            firmware.version,
            pos
        ));
    };

    let source = match url {
        Some(url) => ResolvedFirmwareArtifactSource::Remote {
            url: url.to_owned(),
            sha256: artifact.sha256.clone(),
        },
        None => ResolvedFirmwareArtifactSource::Local,
    };

    Ok(Some(ResolvedFirmwareArtifact { local_path, source }))
}

#[cfg(test)]
mod tests {
    use model::firmware::FirmwareFileArtifact;

    use super::*;

    #[test]
    fn resolve_files_firmware_artifact_uses_url_as_remote_source() {
        let firmware_cache_directory = Path::new("/mnt/persistence/fw/download-cache");
        let firmware = firmware_with_files(vec![FirmwareFileArtifact {
            filename: None,
            url: Some("https://firmware.example.invalid/path/fw.bin".to_string()),
            sha256: "abc123".to_string(),
        }]);

        let artifact = resolve_files_firmware_artifact(firmware_cache_directory, &firmware, 0)
            .unwrap()
            .unwrap();

        assert!(artifact.local_path.starts_with(firmware_cache_directory));
        assert_eq!(artifact.local_path.file_name().unwrap(), "fw.bin");
        assert_eq!(
            artifact.source,
            ResolvedFirmwareArtifactSource::Remote {
                url: "https://firmware.example.invalid/path/fw.bin".to_string(),
                sha256: "abc123".to_string(),
            }
        );
    }

    #[test]
    fn resolve_files_firmware_artifact_uses_filename_as_local_source() {
        let firmware = firmware_with_files(vec![FirmwareFileArtifact {
            filename: Some("/opt/carbide/firmware/fw.bin".to_string()),
            url: None,
            sha256: "abc123".to_string(),
        }]);

        let artifact = resolve_files_firmware_artifact(Path::new("/cache"), &firmware, 0)
            .unwrap()
            .unwrap();

        assert_eq!(
            artifact.local_path,
            PathBuf::from("/opt/carbide/firmware/fw.bin")
        );
        assert_eq!(artifact.source, ResolvedFirmwareArtifactSource::Local);
    }

    #[test]
    fn resolve_files_firmware_artifact_gives_url_precedence_over_filename() {
        let firmware_cache_directory = Path::new("/mnt/persistence/fw/download-cache");
        let firmware = firmware_with_files(vec![FirmwareFileArtifact {
            filename: Some("/opt/carbide/firmware/local.bin".to_string()),
            url: Some("https://firmware.example.invalid/remote.bin".to_string()),
            sha256: "abc123".to_string(),
        }]);

        let artifact = resolve_files_firmware_artifact(firmware_cache_directory, &firmware, 0)
            .unwrap()
            .unwrap();

        assert!(artifact.local_path.starts_with(firmware_cache_directory));
        assert_eq!(artifact.local_path.file_name().unwrap(), "remote.bin");
        assert_eq!(
            artifact.source,
            ResolvedFirmwareArtifactSource::Remote {
                url: "https://firmware.example.invalid/remote.bin".to_string(),
                sha256: "abc123".to_string(),
            }
        );
    }

    #[test]
    fn resolve_files_firmware_artifact_returns_none_without_files() {
        let firmware = FirmwareEntry::standard("1.0");

        let artifact = resolve_files_firmware_artifact(Path::new("/cache"), &firmware, 0).unwrap();

        assert_eq!(artifact, None);
    }

    #[test]
    fn resolve_files_firmware_artifact_rejects_url_without_filename() {
        let firmware = firmware_with_files(vec![FirmwareFileArtifact {
            filename: None,
            url: Some("https://firmware.example.invalid/".to_string()),
            sha256: "abc123".to_string(),
        }]);

        let error = resolve_files_firmware_artifact(Path::new("/cache"), &firmware, 0)
            .unwrap_err()
            .to_string();

        assert!(error.contains("URL does not include a filename"));
    }

    fn firmware_with_files(files: Vec<FirmwareFileArtifact>) -> FirmwareEntry {
        FirmwareEntry {
            version: "1.0".to_string(),
            files,
            ..FirmwareEntry::default()
        }
    }
}
