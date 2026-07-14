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

use std::path::{Component, Path};

use carbide_firmware::resolve_files_firmware_artifact;
pub(crate) use carbide_firmware::{ResolvedFirmwareArtifact, ResolvedFirmwareArtifactSource};
use carbide_utils::none_if_empty::NoneIfEmpty;
use eyre::eyre;
use model::firmware::{FirmwareEntry, FirmwareFileArtifact};
use state_controller::state_handler::StateHandlerError;

use crate::rpc::scout_firmware_upgrade::FileArtifact;

pub(crate) fn resolve_firmware_artifact(
    firmware_download_cache_directory: &Path,
    firmware: &FirmwareEntry,
    pos: u32,
) -> Result<ResolvedFirmwareArtifact, StateHandlerError> {
    match resolve_files_firmware_artifact(firmware_download_cache_directory, firmware, pos)
        .map_err(StateHandlerError::GenericError)?
    {
        Some(artifact) => Ok(artifact),
        None => Ok(ResolvedFirmwareArtifact {
            local_path: firmware.get_filename(pos),
            source: ResolvedFirmwareArtifactSource::Local,
        }),
    }
}

pub(crate) fn resolve_scout_file_artifact(
    pxe_public_base_url: &str,
    firmware_directory: &Path,
    artifact: &FirmwareFileArtifact,
) -> Result<FileArtifact, StateHandlerError> {
    let url = artifact.url.as_deref().map(str::trim).none_if_empty();

    let filename = artifact.filename.as_deref().map(str::trim).none_if_empty();

    let url = if let Some(url) = url {
        url.to_owned()
    } else if let Some(filename) = filename {
        firmware_artifact_url(pxe_public_base_url, firmware_directory, filename)?
    } else {
        return Err(StateHandlerError::GenericError(eyre!(
            "scout firmware artifact has no filename or URL"
        )));
    };

    Ok(FileArtifact {
        url,
        sha256: artifact.sha256.clone(),
    })
}

fn firmware_artifact_url(
    pxe_public_base_url: &str,
    firmware_directory: &Path,
    path: &str,
) -> Result<String, StateHandlerError> {
    let relative = Path::new(path)
        .strip_prefix(firmware_directory)
        .map_err(|_| {
            StateHandlerError::GenericError(eyre!(
                "firmware artifact path {path} is outside firmware directory {}",
                firmware_directory.display()
            ))
        })?;

    if !relative
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(StateHandlerError::GenericError(eyre!(
            "firmware artifact path {path} contains unsafe path components"
        )));
    }

    let relative = relative.to_str().ok_or_else(|| {
        StateHandlerError::GenericError(eyre!("firmware artifact path {path} is not valid UTF-8"))
    })?;

    Ok(format!(
        "{}/public/firmware/{relative}",
        pxe_public_base_url.trim_end_matches('/')
    ))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const FIRMWARE_DOWNLOAD_CACHE_DIRECTORY: &str = "/mnt/persistence/fw/download-cache";

    #[test]
    fn resolves_files_artifact_with_url_and_filename() {
        let firmware = firmware_with_files(vec![FirmwareFileArtifact {
            filename: Some("/opt/nico/firmware/fw.bin".to_string()),
            url: Some("https://firmware.example.invalid/fw.bin".to_string()),
            sha256: "abc123".to_string(),
        }]);

        let artifact =
            resolve_firmware_artifact(Path::new(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY), &firmware, 0)
                .unwrap();

        assert!(
            artifact
                .local_path
                .starts_with(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY)
        );
        assert_eq!(artifact.local_path.file_name().unwrap(), "fw.bin");
        assert_eq!(
            artifact.source,
            ResolvedFirmwareArtifactSource::Remote {
                url: "https://firmware.example.invalid/fw.bin".to_string(),
                sha256: "abc123".to_string(),
            }
        );
    }

    #[test]
    fn derives_files_artifact_filename_from_url_when_filename_is_missing() {
        let firmware = firmware_with_files(vec![FirmwareFileArtifact {
            filename: None,
            url: Some("https://firmware.example.invalid/path/fw_image.bin".to_string()),
            sha256: "abc123".to_string(),
        }]);

        let artifact =
            resolve_firmware_artifact(Path::new(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY), &firmware, 0)
                .unwrap();

        assert!(
            artifact
                .local_path
                .starts_with(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY)
        );
        assert_eq!(artifact.local_path.file_name().unwrap(), "fw_image.bin");
        assert_eq!(
            artifact
                .local_path
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .len(),
            64
        );
    }

    #[test]
    fn resolves_files_artifact_by_index() {
        let firmware = firmware_with_files(vec![
            FirmwareFileArtifact {
                filename: Some("/opt/nico/firmware/first.bin".to_string()),
                url: Some("https://firmware.example.invalid/first.bin".to_string()),
                sha256: "first-sha".to_string(),
            },
            FirmwareFileArtifact {
                filename: Some("/opt/nico/firmware/second.bin".to_string()),
                url: Some("https://firmware.example.invalid/second.bin".to_string()),
                sha256: "second-sha".to_string(),
            },
        ]);

        let artifact =
            resolve_firmware_artifact(Path::new(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY), &firmware, 1)
                .unwrap();

        assert!(
            artifact
                .local_path
                .starts_with(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY)
        );
        assert_eq!(artifact.local_path.file_name().unwrap(), "second.bin");
        assert_eq!(
            artifact.source,
            ResolvedFirmwareArtifactSource::Remote {
                url: "https://firmware.example.invalid/second.bin".to_string(),
                sha256: "second-sha".to_string(),
            }
        );
    }

    #[test]
    fn resolves_files_artifact_without_url_as_local_file() {
        let firmware = firmware_with_files(vec![FirmwareFileArtifact {
            filename: Some("/opt/nico/firmware/fw.bin".to_string()),
            url: None,
            sha256: "abc123".to_string(),
        }]);

        let artifact =
            resolve_firmware_artifact(Path::new(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY), &firmware, 0)
                .unwrap();

        assert_eq!(
            artifact.local_path,
            PathBuf::from("/opt/nico/firmware/fw.bin")
        );
        assert_eq!(artifact.source, ResolvedFirmwareArtifactSource::Local);
    }

    #[test]
    fn files_artifact_index_out_of_range_is_an_error() {
        let firmware = firmware_with_files(vec![FirmwareFileArtifact {
            filename: Some("/opt/nico/firmware/fw.bin".to_string()),
            url: None,
            sha256: "abc123".to_string(),
        }]);

        let error =
            resolve_firmware_artifact(Path::new(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY), &firmware, 1)
                .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("has no files[] artifact at index 1")
        );
    }

    #[test]
    fn files_artifact_without_filename_or_url_is_an_error() {
        let firmware = firmware_with_files(vec![FirmwareFileArtifact {
            filename: None,
            url: None,
            sha256: "abc123".to_string(),
        }]);

        let error =
            resolve_firmware_artifact(Path::new(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY), &firmware, 0)
                .unwrap_err();

        assert!(error.to_string().contains("has no filename or URL"));
    }

    #[test]
    fn files_artifact_url_without_filename_is_an_error() {
        let firmware = firmware_with_files(vec![FirmwareFileArtifact {
            filename: None,
            url: Some("https://firmware.example.invalid/".to_string()),
            sha256: "abc123".to_string(),
        }]);

        let error =
            resolve_firmware_artifact(Path::new(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY), &firmware, 0)
                .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("URL does not include a filename")
        );
    }

    #[test]
    fn legacy_firmware_ignores_top_level_url_and_resolves_as_local_source() {
        let firmware = FirmwareEntry {
            version: "1.0".to_string(),
            filename: None,
            filenames: vec![
                "/opt/nico/firmware/first.bin".to_string(),
                "/opt/nico/firmware/second.bin".to_string(),
            ],
            url: Some("https://firmware.example.invalid/legacy.bin".to_string()),
            checksum: Some("legacy-sha".to_string()),
            ..FirmwareEntry::default()
        };

        let artifact =
            resolve_firmware_artifact(Path::new(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY), &firmware, 1)
                .unwrap();

        assert_eq!(
            artifact.local_path,
            PathBuf::from("/opt/nico/firmware/second.bin")
        );
        assert_eq!(artifact.source, ResolvedFirmwareArtifactSource::Local);
    }

    #[test]
    fn legacy_firmware_without_url_resolves_as_local_source() {
        let firmware = FirmwareEntry {
            version: "1.0".to_string(),
            filename: Some("/opt/nico/firmware/fw.bin".to_string()),
            url: None,
            checksum: None,
            ..FirmwareEntry::default()
        };

        let artifact =
            resolve_firmware_artifact(Path::new(FIRMWARE_DOWNLOAD_CACHE_DIRECTORY), &firmware, 0)
                .unwrap();

        assert_eq!(
            artifact.local_path,
            PathBuf::from("/opt/nico/firmware/fw.bin")
        );
        assert_eq!(artifact.source, ResolvedFirmwareArtifactSource::Local);
    }

    #[test]
    fn resolve_scout_file_artifact_uses_direct_url_when_url_and_filename_are_set() {
        let artifact = FirmwareFileArtifact {
            filename: Some("/opt/nico/firmware/nvidia/fw.bin".to_string()),
            url: Some("https://firmware.example.invalid/fw.bin".to_string()),
            sha256: "abc123".to_string(),
        };

        let file_artifact = resolve_scout_file_artifact(
            "http://carbide-pxe.forge:8080",
            Path::new("/opt/nico/firmware"),
            &artifact,
        )
        .expect("artifact should resolve");

        assert_eq!(file_artifact.url, "https://firmware.example.invalid/fw.bin");
        assert_eq!(file_artifact.sha256, "abc123");
    }

    #[test]
    fn resolve_scout_file_artifact_uses_pxe_url_for_filename_without_url() {
        let artifact = FirmwareFileArtifact {
            filename: Some("/opt/nico/firmware/nvidia/fw.bin".to_string()),
            url: None,
            sha256: "abc123".to_string(),
        };

        let file_artifact = resolve_scout_file_artifact(
            "http://carbide-pxe.forge:8080/",
            Path::new("/opt/nico/firmware"),
            &artifact,
        )
        .expect("artifact should resolve");

        assert_eq!(
            file_artifact.url,
            "http://carbide-pxe.forge:8080/public/firmware/nvidia/fw.bin"
        );
        assert_eq!(file_artifact.sha256, "abc123");
    }

    #[test]
    fn resolve_scout_file_artifact_uses_direct_url_without_filename() {
        let artifact = FirmwareFileArtifact {
            filename: None,
            url: Some("https://firmware.example.invalid/fw.bin".to_string()),
            sha256: "abc123".to_string(),
        };

        let file_artifact = resolve_scout_file_artifact(
            "http://carbide-pxe.forge:8080",
            Path::new("/opt/nico/firmware"),
            &artifact,
        )
        .expect("artifact should resolve");

        assert_eq!(file_artifact.url, "https://firmware.example.invalid/fw.bin");
        assert_eq!(file_artifact.sha256, "abc123");
    }

    #[test]
    fn resolve_scout_file_artifact_requires_filename_or_url() {
        let artifact = FirmwareFileArtifact {
            filename: None,
            url: None,
            sha256: "abc123".to_string(),
        };

        let error = resolve_scout_file_artifact(
            "http://carbide-pxe.forge:8080",
            Path::new("/opt/nico/firmware"),
            &artifact,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("scout firmware artifact has no filename or URL")
        );
    }

    #[test]
    fn resolve_scout_file_artifact_rejects_unsafe_filename_paths() {
        let unsafe_cases = [
            (
                // A sibling directory with the same string prefix is not inside the firmware root.
                "/opt/nico/firmware2/nvidia/dgxh100/cx7/cx7.bin",
                "is outside firmware directory /opt/nico/firmware",
            ),
            (
                // A path under the firmware root still cannot traverse back out with `..`.
                "/opt/nico/firmware/../cx7.bin",
                "contains unsafe path components",
            ),
        ];

        for (filename, expected_error) in unsafe_cases {
            let artifact = FirmwareFileArtifact {
                filename: Some(filename.to_string()),
                url: None,
                sha256: "abc123".to_string(),
            };

            let error = resolve_scout_file_artifact(
                "http://carbide-pxe.forge:8080",
                Path::new("/opt/nico/firmware"),
                &artifact,
            )
            .unwrap_err();

            assert!(error.to_string().contains(expected_error));
        }
    }

    fn firmware_with_files(files: Vec<FirmwareFileArtifact>) -> FirmwareEntry {
        FirmwareEntry {
            version: "1.0".to_string(),
            files,
            ..FirmwareEntry::default()
        }
    }
}
