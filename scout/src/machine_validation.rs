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
    machine_validation_error: Option<String>,
) -> Result<(), CarbideClientError> {
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(rpc::MachineValidationCompletedRequest {
        machine_id: Some(machine_id.to_string().into()),
        machine_validation_error,
    });
    client.machine_validation_completed(request).await?;
    Ok(())
}
