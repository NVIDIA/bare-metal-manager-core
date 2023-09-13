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
use super::{rpc, CarbideCliResult};
use crate::Config;
use prettytable::{row, Table};

pub async fn trigger_reprovisioning(
    id: String,
    set: bool,
    update_firmware: bool,
    api_config: Config,
) -> CarbideCliResult<()> {
    rpc::trigger_dpu_reprovisioning(id, set, update_firmware, api_config).await
}

pub async fn list_dpus_pending(api_config: Config) -> CarbideCliResult<()> {
    let response = rpc::list_dpu_pending_for_reprovisioning(api_config).await?;
    print_pending_dpus(response);
    Ok(())
}

fn print_pending_dpus(dpus: ::rpc::forge::DpuReprovisioningListResponse) {
    let mut table = Table::new();

    table.add_row(row![
        "Id",
        "State",
        "Initiator",
        "Requested At",
        "Update Firmware"
    ]);

    for dpu in dpus.dpus {
        table.add_row(row![
            dpu.id.unwrap_or_default().to_string(),
            dpu.state,
            dpu.initiator,
            dpu.requested_at.unwrap_or_default(),
            dpu.update_firmware
        ]);
    }

    table.printstd();
}
