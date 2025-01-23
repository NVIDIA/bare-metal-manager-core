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

use super::rpc;
use crate::cfg::cli_options::MachineQuery;
use ::rpc::forge_tls_client::ApiConfig;
use utils::admin_cli::CarbideCliResult;

pub async fn set_host_uefi_password(
    query: MachineQuery,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let response = rpc::set_host_uefi_password(query.clone(), api_config).await?;
    println!(
        "successfully set UEFI password for host {query:#?} (jid: {:#?})",
        response.job_id
    );
    Ok(())
}

pub async fn clear_host_uefi_password(
    query: MachineQuery,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let response = rpc::clear_host_uefi_password(query.clone(), api_config).await?;
    println!(
        "successfully cleared UEFI password for host {query:#?}; (jid: {:#?})",
        response.job_id
    );
    Ok(())
}
