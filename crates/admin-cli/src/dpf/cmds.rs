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

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};
use prettytable::row;
use rpc::admin_cli::CarbideCliError;

use crate::dpf::args::DpfQuery;
use crate::rpc::ApiClient;

pub async fn modify_dpf_state(
    query: &DpfQuery,
    _format: OutputFormat, // TODO: Implement json output handling.
    api_client: &ApiClient,
    enabled: bool,
) -> CarbideCliResult<()> {
    let Some(host) = query.host else {
        return Err(CarbideCliError::GenericError(
            "Host id is required!!".to_string(),
        ));
    };

    if host.machine_type() != carbide_uuid::machine::MachineType::Host {
        return Err(CarbideCliError::GenericError(
            "Only host id is expected!!".to_string(),
        ));
    }
    api_client.modify_dpf_state(host, enabled).await?;
    println!("DPF state modified for machine {host} with state {enabled} successfully!!",);
    Ok(())
}

pub async fn show(
    query: &DpfQuery,
    _format: OutputFormat,
    page_size: usize,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let machine_ids = if let Some(host) = query.host {
        if host.machine_type() != carbide_uuid::machine::MachineType::Host {
            return Err(CarbideCliError::GenericError(
                "Only host id is expected!!".to_string(),
            ));
        }
        vec![host]
    } else {
        api_client
            .0
            .find_machine_ids(::rpc::forge::MachineSearchConfig {
                include_dpus: false,
                include_predicted_host: true,
                ..Default::default()
            })
            .await?
            .machine_ids
    };

    let response = api_client.get_dpf_state(machine_ids, page_size).await?;
    if response.is_empty() {
        println!("No DPF state found for machines");
        return Ok(());
    }

    if response.len() == 1 {
        println!(
            "DPF state for machine {}: {}",
            response[0].machine_id.unwrap_or_default(),
            response[0].dpf_enabled
        );
    } else {
        let mut table = prettytable::Table::new();
        table.set_titles(row!["Id", "State",]);

        for dpf_state in response {
            table.add_row(row![
                dpf_state.machine_id.unwrap_or_default().to_string(),
                dpf_state.dpf_enabled.to_string(),
            ]);
        }
        table.printstd();
    }

    Ok(())
}
