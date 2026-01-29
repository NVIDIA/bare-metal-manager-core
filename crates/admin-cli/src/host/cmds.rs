/*
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::forge::host_reprovisioning_request::Mode;
use ::rpc::forge::{HostReprovisioningRequest, UpdateInitiator};
use carbide_uuid::machine::MachineId;
use forge_secrets::credentials::Credentials;
use prettytable::{Table, row};

use crate::machine::{HealthOverrideTemplates, MachineQuery, get_health_report};
use crate::rpc::ApiClient;

pub async fn trigger_reprovisioning(
    host_id: MachineId,
    mode: Mode,
    api_client: &ApiClient,
    update_message: Option<String>,
) -> CarbideCliResult<()> {
    if let (Mode::Set, Some(update_message)) = (mode, update_message) {
        // Set a HostUpdateInProgress health override on the Host

        let host_machine = api_client
            .get_machines_by_ids(&[host_id])
            .await?
            .machines
            .into_iter()
            .next();

        if let Some(host_machine) = host_machine
            && host_machine
                .health_overrides
                .iter()
                .any(|or| or.source == "host-update")
        {
            return Err(CarbideCliError::GenericError(format!(
                "Host machine: {:?} already has a \"host-update\" override.",
                host_machine.id,
            )));
        }

        let report = get_health_report(HealthOverrideTemplates::HostUpdate, Some(update_message));

        api_client
            .machine_insert_health_report_override(host_id, report.into(), false)
            .await?;
    }
    api_client
        .0
        .trigger_host_reprovisioning(HostReprovisioningRequest {
            machine_id: Some(host_id),
            mode: mode as i32,
            initiator: UpdateInitiator::AdminCli as i32,
        })
        .await?;

    Ok(())
}

pub async fn list_hosts_pending(api_client: &ApiClient) -> CarbideCliResult<()> {
    let response = api_client.0.list_hosts_waiting_for_reprovisioning().await?;
    print_pending_hosts(response);
    Ok(())
}

pub async fn set_uefi_password(
    query: &MachineQuery,
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

pub async fn clear_uefi_password(
    query: &MachineQuery,
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

pub fn generate_uefi_password() -> CarbideCliResult<()> {
    let password = Credentials::generate_password_no_special_char();
    println!("Generated Bios Admin Password: {password}");
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
