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

use super::rpc;
use crate::{
    cfg::carbide_options::ShowBmcMachine, machine::MachineFilter, CarbideCliResult, Config,
};
use ::rpc::forge::{self as forgerpc, BmcMachineType};
use prettytable::{row, Table};

pub async fn handle_show(
    args: ShowBmcMachine,
    json: bool,
    api_config: Config,
) -> CarbideCliResult<()> {
    if args.all || args.dpus || args.hosts {
        let f: MachineFilter = MachineFilter {
            only_dpus: args.dpus,
            only_hosts: args.hosts,
        };
        show_all_bmc_machines(json, api_config, f).await?;
    } else if let Some(bmc_machine_id) = args.bmc_machine {
        show_bmc_machine_information(bmc_machine_id, json, api_config).await?;
    }

    Ok(())
}

async fn show_bmc_machine_information(
    bmc_machine_id: String,
    json: bool,
    api_config: Config,
) -> CarbideCliResult<()> {
    let bmc_machine_list = rpc::get_bmc_machine(api_config, bmc_machine_id).await?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&bmc_machine_list).unwrap()
        );
    } else {
        convert_bmc_machines_to_nice_table(bmc_machine_list).printstd();
    }
    Ok(())
}

async fn show_all_bmc_machines(
    json: bool,
    api_config: Config,
    f: MachineFilter,
) -> CarbideCliResult<()> {
    let mut bmc_machine_list = rpc::get_all_bmc_machines(api_config).await?;
    if f.only_dpus {
        bmc_machine_list
            .bmc_machines
            .retain(|m| m.bmc_type == forgerpc::BmcMachineType::DpuBmc as i32);
    } else if f.only_hosts {
        bmc_machine_list
            .bmc_machines
            .retain(|m| m.bmc_type == forgerpc::BmcMachineType::HostBmc as i32);
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&bmc_machine_list).unwrap()
        );
    } else {
        convert_bmc_machines_to_nice_table(bmc_machine_list).printstd();
    }
    Ok(())
}

fn convert_bmc_machines_to_nice_table(bmc_machine_list: forgerpc::BmcMachineList) -> Box<Table> {
    let mut table: Table = Table::new();

    table.add_row(row![
        "Id",
        "State",
        "IP Address",
        "Hostname",
        "MAC Address",
        "Type",
        "FW version",
        "Attached DPU machine"
    ]);

    for bmc_machine in bmc_machine_list.bmc_machines {
        let bmc_type = if bmc_machine.bmc_type == BmcMachineType::DpuBmc as i32 {
            "DPU"
        } else {
            "HOST"
        };

        table.add_row(row![
            bmc_machine.id,
            bmc_machine.state.to_uppercase(),
            bmc_machine.ip_address,
            bmc_machine.hostname,
            bmc_machine.mac_address,
            bmc_type,
            bmc_machine.fw_version,
            bmc_machine.machine_id,
        ]);
    }

    table.into()
}
