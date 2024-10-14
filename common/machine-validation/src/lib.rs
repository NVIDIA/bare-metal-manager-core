/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use errors::MachineValidationError;
use flate2::write::GzDecoder;
use futures_util::StreamExt;
use machine_validation::Suite;
use serde::{Deserialize, Serialize};
use tar::Archive;

use std::cmp::min;
use std::fs::File;
use std::time::Duration;

use std::io::Write;

mod errors;
mod machine_validation;

pub const MACHINE_VALIDATION_SERVER: &str = "carbide-pxe.forge";
pub const SCHME: &str = "http";
pub const MACHINE_VALIDATION_CONFIG_PATH: &str =
    "/public/blobs/internal/machine-validation/config/";
pub const MACHINE_VALIDATION_CONFIG_TAR: &str = "config.tar";

pub const MACHINE_VALIDATION_IMAGE_PATH: &str = "/public/blobs/internal/machine-validation/images/";
pub const MACHINE_VALIDATION_CONFIG_FILE: &str = "/tmp/config.yaml";
pub const MACHINE_VALIDATION_IMAGE_FILE: &str = "/tmp/machine_validation.tar";
pub const MACHINE_VALIDATION_RUNNER_BASE_PATH: &str = "nvcr.io/nvidian/nvforge/";
pub const MACHINE_VALIDATION_RUNNER_TAG: &str = "latest";
pub const IMAGE_LIST_FILE: &str = "/tmp/list.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineValidationConfiguration {
    #[serde(rename = "ExternalConfigs")]
    pub external_configs: Option<Vec<String>>,
    #[serde(rename = "Tests")]
    pub suite: Suite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineValidationOptions {
    pub api: String,
    pub root_ca: String,
    pub client_cert: String,
    pub client_key: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineValidation {
    options: MachineValidationOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MachineValidationFilter {
    pub tags: Vec<String>,
    pub allowed_tests: Vec<String>,
}

pub struct MachineValidationManager {}

impl MachineValidationManager {
    pub fn read_yaml_data(
        file_name: &str,
    ) -> Result<MachineValidationConfiguration, MachineValidationError> {
        let yaml_content = match std::fs::read_to_string(file_name) {
            Ok(content) => content,
            Err(e) => {
                return Err(MachineValidationError::ConfigFileRead(e.to_string()));
            }
        };
        let parsed_data: Result<MachineValidationConfiguration, serde_yaml::Error> =
            serde_yaml::from_str(&yaml_content);
        let config = match parsed_data {
            Ok(data) => data,
            Err(e) => return Err(MachineValidationError::Parse(e.to_string())),
        };
        Ok(config)
    }

    pub async fn download_file(url: &str, output_file: &str) -> Result<(), MachineValidationError> {
        let client = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| MachineValidationError::Generic(format!("Client builder error: {e}")))?;

        let res = client
            .get(url)
            .send()
            .await
            .or(Err(MachineValidationError::Generic(format!(
                "Failed to GET from '{}'",
                &url
            ))))?;
        let total_size = res
            .content_length()
            .ok_or(MachineValidationError::Generic(format!(
                "Failed to get content length from '{}'",
                &url
            )))?;
        let _ = std::fs::remove_file(output_file).or(Err(MachineValidationError::Generic(
            format!("Failed to delete file '{}'", output_file),
        )));

        let mut file = std::fs::File::create(output_file).or(Err(
            MachineValidationError::Generic(format!("Failed to create file '{}'", output_file)),
        ))?;
        let mut buffer: u64 = 0;
        let mut stream = res.bytes_stream();

        while let Some(item) = stream.next().await {
            let chunk = item.or(Err(MachineValidationError::Generic(
                "Error while reading stream".to_string(),
            )))?;
            file.write_all(&chunk)
                .or(Err(MachineValidationError::Generic(
                    "Error while writing to file".to_string(),
                )))?;
            let new = min(buffer + (chunk.len() as u64), total_size);
            buffer = new;
        }
        Ok(())
    }
    pub async fn get_config_file(platform_name: String) -> Result<String, MachineValidationError> {
        tracing::info!(platform_name);
        let path: String = format!("/tmp/config/{}.yaml", platform_name);
        if std::fs::metadata(path.clone()).is_err() {
            return Ok("/tmp/config/default.yaml".to_string());
        }
        Ok(path)
    }

    pub async fn get_machine_validation_config_files() -> Result<(), MachineValidationError> {
        let url: String = format!(
            "{}://{}{}{}",
            SCHME,
            MACHINE_VALIDATION_SERVER,
            MACHINE_VALIDATION_CONFIG_PATH,
            MACHINE_VALIDATION_CONFIG_TAR
        );
        tracing::info!(url);
        let output_file = format!("/tmp/{}", MACHINE_VALIDATION_CONFIG_TAR);
        Self::download_file(&url, output_file.as_str()).await?;

        let tar_gz = File::open(output_file)
            .map_err(|e| MachineValidationError::Generic(format!("File: {e}")))?;
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);
        archive
            .unpack("/tmp/config/")
            .map_err(|e| MachineValidationError::Generic(format!("Archive: {e}")))?;

        Ok(())
    }
    pub async fn run(
        machine_id: &str,
        platform_name: String,
        options: MachineValidationOptions,
        context: String,
        uuid: String,
        machine_validation_filter: MachineValidationFilter,
    ) -> Result<(), MachineValidationError> {
        let mc = MachineValidation::new(options);
        match Self::get_machine_validation_config_files().await {
            Ok(_) => println!("fetch config files complete"),
            Err(e) => {
                println!("{}", e);
                return Err(e);
            }
        }
        let config_file = Self::get_config_file(platform_name).await?;

        let mvc = Self::read_yaml_data(&config_file)
            .map_err(|e| MachineValidationError::Generic(format!("Machine Validation: {e}")))?;

        mc.clone()
            .download_external_config(mvc.external_configs)
            .await?;
        mc.run(
            machine_id,
            mvc.suite,
            context,
            uuid,
            true,
            machine_validation_filter,
        )
        .await?;

        Ok(())
    }
}
