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

use std::cmp::min;
use std::io::Write;
use std::time::Duration;

use carbide_uuid::machine::MachineId;
use errors::MachineValidationError;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};

mod errors;
mod machine_validation;

pub const MACHINE_VALIDATION_SERVER: &str = "carbide-pxe.forge";
pub const SCHME: &str = "http";

pub const MACHINE_VALIDATION_IMAGE_PATH: &str = "/public/blobs/internal/machine-validation/images/";
pub const MACHINE_VALIDATION_IMAGE_FILE: &str = "/tmp/machine_validation.tar";
pub const MACHINE_VALIDATION_RUNNER_BASE_PATH: &str = "nvcr.io/nvidian/nvforge/";
pub const MACHINE_VALIDATION_RUNNER_TAG: &str = "latest";
pub const IMAGE_LIST_FILE: &str = "/tmp/list.json";

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
    pub run_unverfied_tests: Option<bool>,
    pub contexts: Option<Vec<String>>,
}

pub struct MachineValidationManager {}

impl MachineValidationManager {
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
            format!("Failed to delete file '{output_file}'"),
        )));

        let mut file = std::fs::File::create(output_file).or(Err(
            MachineValidationError::Generic(format!("Failed to create file '{output_file}'")),
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

    pub async fn run(
        machine_id: &MachineId,
        platform_name: String,
        options: MachineValidationOptions,
        context: String,
        uuid: String,
        machine_validation_filter: MachineValidationFilter,
    ) -> Result<(), MachineValidationError> {
        let mc = MachineValidation::new(options);

        let tests = mc
            .clone()
            .get_machine_validation_tests(rpc::forge::MachineValidationTestsGetRequest {
                supported_platforms: vec![platform_name],
                contexts: if machine_validation_filter
                    .clone()
                    .contexts
                    .unwrap_or_default()
                    .is_empty()
                {
                    vec![context.clone()]
                } else {
                    machine_validation_filter
                        .clone()
                        .contexts
                        .unwrap_or_default()
                },
                is_enabled: Some(true),
                verified: if machine_validation_filter
                    .run_unverfied_tests
                    .unwrap_or(false)
                {
                    None // This indicates run all tests including un verified
                } else {
                    Some(true)
                },
                custom_tags: machine_validation_filter.clone().tags,
                ..rpc::forge::MachineValidationTestsGetRequest::default()
            })
            .await?;
        let mut run_request = rpc::forge::MachineValidationRunRequest {
            validation_id: Some(rpc::Uuid {
                value: uuid.to_owned(),
            }),
            ..rpc::forge::MachineValidationRunRequest::default()
        };
        let mut expected_time_duration = 0;
        for test in tests.clone() {
            if !machine_validation_filter.allowed_tests.is_empty()
                && !machine_validation_filter
                    .allowed_tests
                    .contains(&test.test_id)
            {
                continue;
            }
            run_request.total += 1;
            expected_time_duration += test.timeout.unwrap_or(7200);
        }
        run_request.duration_to_complete = Some(rpc::Duration::from(
            std::time::Duration::from_secs(expected_time_duration as u64),
        ));
        //Update the duration
        mc.clone()
            .update_machine_validation_run(run_request)
            .await?;
        mc.run(
            machine_id,
            tests,
            context,
            uuid,
            true,
            machine_validation_filter,
        )
        .await?;

        Ok(())
    }
}
