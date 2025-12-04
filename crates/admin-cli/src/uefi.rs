/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::admin_cli::CarbideCliResult;
use carbide_uuid::machine::MachineId;

use crate::cfg::cli_options::MachineQuery;
use crate::rpc::ApiClient;

pub async fn set_host_uefi_password(
    query: MachineQuery,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let response = api_client
        .0
        .set_host_uefi_password(query.query.parse::<MachineId>()?)
        .await?;
    println!(
        "successfully set UEFI password for host {query:#?} (jid: {:#?})",
        response.job_id
    );
    Ok(())
}

pub async fn clear_host_uefi_password(
    query: MachineQuery,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let response = api_client
        .0
        .clear_host_uefi_password(query.query.parse::<MachineId>()?)
        .await?;
    println!(
        "successfully cleared UEFI password for host {query:#?}; (jid: {:#?})",
        response.job_id
    );
    Ok(())
}
