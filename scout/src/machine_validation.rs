/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge as rpc;

use crate::{cfg::Options, client::create_forge_client, CarbideClientError};

pub(crate) async fn completed(
    config: &Options,
    machine_id: &str,
    uuid: String,
    machine_validation_error: Option<String>,
) -> Result<(), CarbideClientError> {
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(rpc::MachineValidationCompletedRequest {
        machine_id: Some(machine_id.to_string().into()),
        machine_validation_error,
        validation_id: Some(::rpc::common::Uuid { value: uuid }),
    });
    client.machine_validation_completed(request).await?;
    Ok(())
}

pub(crate) async fn persist(
    config: &Options,
    data: Option<rpc::MachineValidationResult>,
) -> Result<(), CarbideClientError> {
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(rpc::MachineValidationResultPostRequest { result: data });
    client.persist_validation_result(request).await?;
    Ok(())
}

pub(crate) async fn run(
    config: &Options,
    uuid: String,
    context: String,
) -> Result<(), CarbideClientError> {
    // Sample data
    let data = Some(rpc::MachineValidationResult {
        name: "test".to_string(),
        description: "test".to_string(),
        command: "echo".to_string(),
        args: "".to_string(),
        std_out: "".to_string(),
        std_err: "".to_string(),
        context,
        exit_code: 0,
        start_time: None,
        end_time: None,
        validation_id: Some(::rpc::common::Uuid { value: uuid }),
    });
    persist(config, data).await?;
    Ok(())
}
