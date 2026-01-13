/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::admin_cli::{CarbideCliError, OutputFormat};
use prettytable::{Cell, Row, Table, row};

use super::Opts;
use crate::rpc::ApiClient;

macro_rules! r {
    ($table: ident, $value:ident, $field_name:ident) => {
        $table.add_row(Row::new(vec![
            Cell::new(stringify!($field_name)),
            Cell::new(&$value.$field_name.to_string()),
        ]));
    };
}

macro_rules! rv {
    ($table: ident, $value:ident, $field_name:ident) => {
        $table.add_row(Row::new(vec![
            Cell::new(stringify!($field_name)),
            Cell::new(
                &$value
                    .$field_name
                    .chunks(5)
                    .map(|x| x.join(", "))
                    .collect::<Vec<String>>()
                    .join("\n"),
            ),
        ]));
    };
}

pub async fn handle_show_version(
    opts: &Opts,
    api_client: &ApiClient,
    format: OutputFormat,
) -> Result<(), CarbideCliError> {
    let v = api_client.0.version(opts.show_runtime_config).await?;
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string(&v)?);
        return Ok(());
    }

    // Same as running `carbide-api --version`
    println!(
        "carbide-api:\n\tbuild_version={}, build_date={}, git_sha={}, rust_version={}, build_user={}, build_hostname={}",
        v.build_version, v.build_date, v.git_sha, v.rust_version, v.build_user, v.build_hostname,
    );
    // Same as running `forge-admin-cli --version`
    println!();
    println!("forge-admin-cli:\n\t{}", carbide_version::version!());

    if opts.show_runtime_config {
        let config = v
            .runtime_config
            .ok_or_else(|| CarbideCliError::GenericError("Config not found.".to_owned()))?;

        println!();
        println!("Runtime Config:");

        let mut table = Table::new();

        table.set_titles(row!["Property", "Value"]);
        r!(table, config, listen);
        r!(table, config, metrics_endpoint);
        r!(table, config, database_url);
        r!(table, config, max_database_connections);
        r!(table, config, enable_route_servers);
        r!(table, config, asn);
        rv!(table, config, dhcp_servers);
        rv!(table, config, route_servers);
        r!(table, config, enable_route_servers);
        rv!(table, config, deny_prefixes);
        rv!(table, config, site_fabric_prefixes);
        rv!(table, config, networks);
        r!(table, config, dpu_ipmi_tool_impl);
        r!(table, config, dpu_ipmi_reboot_attempt);
        table.add_row(Row::new(vec![
            Cell::new("intial_domain_name"),
            Cell::new(config.initial_domain_name()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("sitename"),
            Cell::new(config.sitename()),
        ]));
        r!(table, config, initial_dpu_agent_upgrade_policy);

        if !config.dpu_nic_firmware_update_version.is_empty() {
            let mut version_table = Table::new();
            for (name, value) in config.dpu_nic_firmware_update_version {
                version_table.add_row(Row::new(vec![Cell::new(&name), Cell::new(&value)]));
            }
            table.add_row(row!["dpu_nic_firmware_update_version", version_table]);
        } else {
            table.add_row(row!["dpu_nic_firmware_update_version", "Not Set"]);
        }
        r!(table, config, dpu_nic_firmware_initial_update_enabled);
        r!(table, config, dpu_nic_firmware_reprovision_update_enabled);
        r!(table, config, max_concurrent_machine_updates);
        r!(table, config, machine_update_runtime_interval);
        r!(table, config, nvue_enabled);
        r!(table, config, attestation_enabled);
        r!(table, config, max_find_by_ids);
        r!(table, config, machine_validation_enabled);
        r!(table, config, bom_validation_enabled);
        r!(table, config, bom_validation_ignore_unassigned_machines);
        r!(
            table,
            config,
            bom_validation_allow_allocation_on_validation_failure
        );
        r!(table, config, bom_validation_auto_generate_missing_sku);
        r!(
            table,
            config,
            bom_validation_auto_generate_missing_sku_interval
        );
        r!(table, config, dpa_enabled);
        r!(table, config, mqtt_endpoint);
        r!(table, config, mqtt_broker_port);
        r!(table, config, mqtt_hb_interval);
        r!(table, config, dpa_subnet_ip);
        r!(table, config, dpa_subnet_mask);

        r!(table, config, dpu_secure_boot_enabled);

        _ = table.print_tty(true);
    }

    Ok(())
}
