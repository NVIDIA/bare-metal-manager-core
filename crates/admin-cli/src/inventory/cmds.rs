/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::fs;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::site_explorer::ExploredManagedHost;
use ::rpc::{InstanceList, MachineList};
use carbide_uuid::machine::MachineId;
use serde::{Deserialize, Serialize};

use super::args::Cmd;
use crate::rpc::ApiClient;

// Expected output
// x86_host_bmcs:
//   - all hosts BMC
//
// x86_hosts:
//   - all hosts on admin network, not on tenant network
//
// dpus:
//   - all dpus
//
// instances:
//   children:
//     - tenant_org1
//     - tenant_org2
//
// tenant_org1:
//   - all instances in tenant_org1
//
// Each host/dpu/tenant:
//   ansible_host: IP Address
//   BMC_IP: IP Address
//
type InstanceGroup = HashMap<&'static str, HashMap<String, Option<String>, RandomState>>;

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum TopYamlElement {
    InstanceChildren(InstanceGroup),
    Instance(HashMap<String, HashMap<String, InstanceDetails>>),
    BmcHostInfo(HashMap<String, HashMap<String, BmcInfo>>),
    HostMachineInfo(HashMap<String, HashMap<String, HostMachineInfo>>),
    DpuMachineInfo(HashMap<String, HashMap<String, DpuMachineInfo>>),
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct BmcInfo {
    ansible_host: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_bmc_ip: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct HostMachineInfo {
    ansible_host: String,
    machine_id: String,
    // Deprecated field. Use all_dpu_machine_ids or primary_dpu_machine_id for primary dpu.
    dpu_machine_id: String,
    // Primary DPU
    primary_dpu_machine_id: String,
    all_dpu_machine_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct DpuMachineInfo {
    ansible_host: String,
    machine_id: String,
}

/// Generate element containing all information needed to write a Machine Host.
fn get_host_machine_info(machines: &[&::rpc::Machine]) -> HashMap<String, HostMachineInfo> {
    let mut machine_element: HashMap<String, HostMachineInfo> = HashMap::new();

    for machine in machines {
        let primary_interface = machine.interfaces.iter().find(|x| x.primary_interface);

        if let Some(primary_interface) = primary_interface {
            let hostname = primary_interface.hostname.clone();
            let address = primary_interface.address[0].clone();
            let primary_dpu = primary_interface
                .attached_dpu_machine_id
                .unwrap_or_default()
                .to_string();

            machine_element.insert(
                hostname,
                HostMachineInfo {
                    ansible_host: address,
                    machine_id: machine.id.unwrap_or_default().to_string(),
                    dpu_machine_id: primary_dpu.clone(),
                    primary_dpu_machine_id: primary_dpu,
                    all_dpu_machine_ids: machine
                        .interfaces
                        .iter()
                        .map(|x| x.attached_dpu_machine_id.unwrap_or_default().to_string())
                        .collect::<Vec<String>>(),
                },
            );
        } else {
            eprintln!(
                "Ignoring machine {:?} since no attached primary interface found with it.",
                machine.id
            )
        }
    }

    machine_element
}

/// Generate element containing all information needed to write a Machine Host.
fn get_dpu_machine_info(machines: &[&::rpc::Machine]) -> HashMap<String, DpuMachineInfo> {
    let mut machine_element: HashMap<String, DpuMachineInfo> = HashMap::new();

    for machine in machines {
        let primary_interface = machine.interfaces.iter().find(|x| x.primary_interface);

        if let Some(primary_interface) = primary_interface {
            let hostname = primary_interface.hostname.clone();
            let address = primary_interface.address[0].clone();

            machine_element.insert(
                hostname,
                DpuMachineInfo {
                    ansible_host: address,
                    machine_id: machine.id.unwrap_or_default().to_string(),
                },
            );
        }
    }

    machine_element
}

/// Generate element containing all information needed to write a BMC Host.
fn get_bmc_info(
    machines: &[&::rpc::Machine],
    managed_hosts: Vec<ExploredManagedHost>,
) -> HashMap<String, BmcInfo> {
    let mut bmc_element: HashMap<String, BmcInfo> = HashMap::new();
    let mut known_ips: Vec<String> = Vec::new();

    let mut managed_host_map: HashMap<String, String> = HashMap::new();

    for managed_host in &managed_hosts {
        for dpu in &managed_host.dpus {
            managed_host_map.insert(dpu.bmc_ip.clone(), managed_host.host_bmc_ip.clone());
        }
    }

    for machine in machines {
        let Some(bmc_ip) = machine.bmc_info.as_ref().map(|x| x.ip.clone()) else {
            continue;
        };

        let Some(bmc_ip) = bmc_ip else {
            continue;
        };

        let hostname = machine
            .interfaces
            .iter()
            .find_map(|x| {
                if x.primary_interface {
                    Some(x.hostname.clone())
                } else {
                    None
                }
            })
            .unwrap_or("Not Found".to_string())
            .clone();

        bmc_element.insert(
            format!("{hostname}-bmc"),
            BmcInfo {
                ansible_host: bmc_ip.clone(),
                host_bmc_ip: managed_host_map.get(&bmc_ip).cloned(),
            },
        );

        known_ips.push(bmc_ip);
    }

    for managed_host in managed_hosts {
        for dpu in managed_host.dpus {
            if !known_ips.contains(&dpu.bmc_ip) {
                // Found a undiscovered dpu bmc ip.
                bmc_element.insert(
                    format!("{}-undiscovered-bmc", dpu.bmc_ip),
                    BmcInfo {
                        ansible_host: dpu.bmc_ip.clone(),
                        host_bmc_ip: Some(managed_host.host_bmc_ip.clone()),
                    },
                );
            }
        }
    }

    bmc_element
}

/// Main entry function which print inventory.
pub async fn print_inventory(
    api_client: &ApiClient,
    action: Cmd,
    page_size: usize,
) -> CarbideCliResult<()> {
    let all_machines = api_client
        .get_all_machines(
            rpc::forge::MachineSearchConfig {
                include_predicted_host: true,
                include_dpus: true,
                ..Default::default()
            },
            page_size,
        )
        .await?;
    let all_instances = api_client
        .get_all_instances(None, None, None, None, None, page_size)
        .await?;

    let (instances, used_machine) = create_inventory_for_instances(all_instances, &all_machines)?;

    let children: InstanceGroup = HashMap::from([(
        "children",
        HashMap::from_iter(instances.keys().map(|x| (x.clone(), None))),
    )]);

    let mut final_group: HashMap<String, TopYamlElement> = HashMap::from([(
        "instances".to_string(),
        TopYamlElement::InstanceChildren(children),
    )]);

    let site_report_managed_host = api_client.get_all_explored_managed_hosts(page_size).await?;

    for (key, value) in instances.into_iter() {
        let mut ins_details: HashMap<String, InstanceDetails> = HashMap::new();

        for ins in value {
            ins_details.insert(ins.instance_id.clone(), ins);
        }
        final_group.insert(
            key,
            TopYamlElement::Instance(HashMap::from([("hosts".to_string(), ins_details)])),
        );
    }

    let all_hosts = all_machines
        .machines
        .iter()
        .filter(|m| m.id.is_some_and(|id| id.machine_type().is_host()))
        .collect::<Vec<&::rpc::Machine>>();

    let all_dpus = all_machines
        .machines
        .iter()
        .filter(|m| m.id.is_some_and(|id| id.machine_type().is_dpu()))
        .collect::<Vec<&::rpc::Machine>>();

    final_group.insert(
        "x86_host_bmcs".to_string(),
        TopYamlElement::BmcHostInfo(HashMap::from([(
            "hosts".to_string(),
            get_bmc_info(&all_hosts, vec![]),
        )])),
    );
    final_group.insert(
        "dpu_bmcs".to_string(),
        TopYamlElement::BmcHostInfo(HashMap::from([(
            "hosts".to_string(),
            get_bmc_info(&all_dpus, site_report_managed_host),
        )])),
    );
    let host_on_admin = all_hosts
        .into_iter()
        .filter(|x| !used_machine.contains(&x.id))
        .collect::<Vec<&::rpc::Machine>>();

    final_group.insert(
        "x86_hosts".to_string(),
        TopYamlElement::HostMachineInfo(HashMap::from([(
            "hosts".to_string(),
            get_host_machine_info(&host_on_admin),
        )])),
    );
    final_group.insert(
        "dpus".to_string(),
        TopYamlElement::DpuMachineInfo(HashMap::from([(
            "hosts".to_string(),
            get_dpu_machine_info(&all_dpus),
        )])),
    );
    let output = serde_yaml::to_string(&final_group).map_err(CarbideCliError::YamlError)?;
    if let Some(filename) = action.filename {
        fs::write(filename, output)
            .map_err(|e| CarbideCliError::GenericError(format!("File write error: {e}")))?;
    } else {
        println!("{output}");
    }
    Ok(())
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct InstanceDetails {
    instance_id: String,
    machine_id: String,
    ansible_host: String,
    bmc_ip: String,
}

type CreateInventoryReturnType = (
    HashMap<String, Vec<InstanceDetails>>,
    Vec<Option<MachineId>>,
);

/// Generate inventory item for instances.
fn create_inventory_for_instances(
    instances: InstanceList,
    machines: &MachineList,
) -> CarbideCliResult<CreateInventoryReturnType> {
    let mut tenant_map: HashMap<String, Vec<InstanceDetails>> = HashMap::new();
    let mut used_machines = vec![];

    for instance in instances.instances {
        let if_status = instance
            .status
            .as_ref()
            .and_then(|status| status.network.as_ref())
            .map(|status| status.interfaces.as_slice())
            .unwrap_or_default();

        let physical_ip = if_status.iter().find_map(|x| {
            // For physical interface `virtual_function_id` is None.
            if x.virtual_function_id.is_none() {
                x.addresses.first().map(|x| x.to_string())
            } else {
                None
            }
        });

        let machine = machines
            .machines
            .iter()
            .find(|x| x.id == instance.machine_id)
            .ok_or_else(|| {
                CarbideCliError::GenericError(format!(
                    "No such machine {:?} found in db, instance {:?}",
                    instance.machine_id, instance.id,
                ))
            })?;

        used_machines.push(machine.id);

        let bmc_ip = machine
            .bmc_info
            .as_ref()
            .map(|x| x.ip.clone().unwrap_or_default())
            .unwrap_or_default();

        let details = InstanceDetails {
            instance_id: instance.id.unwrap_or_default().to_string(),
            machine_id: instance.machine_id.unwrap_or_default().to_string(),
            ansible_host: physical_ip.unwrap_or_default(),
            bmc_ip,
        };

        let tenant = instance
            .config
            .and_then(|x| x.tenant)
            .map(|x| x.tenant_organization_id)
            .unwrap_or("Unknown".to_string());

        tenant_map.entry(tenant).or_default().push(details);
    }

    Ok((tenant_map, used_machines))
}
