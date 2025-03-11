/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge::host_reprovisioning_request::Mode;
use ::rpc::forge_tls_client::ApiConfig;
use prettytable::{Table, row};

use super::rpc;
use utils::admin_cli::{CarbideCliError, CarbideCliResult};

pub async fn trigger_reprovisioning(
    host_id: String,
    mode: Mode,
    api_config: &ApiConfig<'_>,
    maintenance_reference: Option<String>,
) -> CarbideCliResult<()> {
    let machine_id = ::rpc::MachineId {
        id: host_id.clone(),
    };
    if let (Mode::Set, Some(mr)) = (mode, &maintenance_reference) {
        // Check host must not be in maintenance mode.
        let host_machine = rpc::get_machines_by_ids(api_config, &[machine_id.clone()])
            .await?
            .machines
            .into_iter()
            .next();

        if let Some(host_machine) = host_machine {
            if host_machine.maintenance_reference.is_some() {
                return Err(CarbideCliError::GenericError(format!(
                    "Host machine: {:?} is already in maintenance.",
                    host_machine.id,
                )));
            }
        }

        let req = ::rpc::forge::MaintenanceRequest {
            operation: ::rpc::forge::MaintenanceOperation::Enable.into(),
            host_id: Some(machine_id),
            reference: Some(mr.clone()),
        };
        rpc::set_maintenance(req, api_config).await?;
    }
    rpc::trigger_host_reprovisioning(host_id.clone(), mode, api_config).await?;

    Ok(())
}

pub async fn list_hosts_pending(api_config: &ApiConfig<'_>) -> CarbideCliResult<()> {
    let response = rpc::list_hosts_pending_for_reprovisioning(api_config).await?;
    print_pending_hosts(response);
    Ok(())
}

fn print_pending_hosts(hosts: ::rpc::forge::HostReprovisioningListResponse) {
    let mut table = Table::new();

    table.set_titles(row![
        "Id",
        "State",
        "Initiator",
        "Requested At",
        "Initiated At",
        "User Approved"
    ]);

    for host in hosts.hosts {
        let user_approval = if host.user_approval_received {
            "Yes"
        } else if host.state.contains("Assigned") {
            "No"
        } else {
            "NA"
        };
        table.add_row(row![
            host.id.unwrap_or_default().to_string(),
            host.state,
            host.initiator,
            host.requested_at.unwrap_or_default(),
            host.initiated_at
                .map(|x| x.to_string())
                .unwrap_or_else(|| "Not Started".to_string()),
            user_approval
        ]);
    }

    table.printstd();
}
