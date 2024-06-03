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
use std::{
    collections::{hash_map::RandomState, HashMap},
    fs,
};

use ::rpc::{forge::MachineType, forge_tls_client::ApiConfig, MachineId};
use ::rpc::{site_explorer::ExploredManagedHost, InstanceList, MachineList};
use serde::{Deserialize, Serialize};

use crate::{cfg::carbide_options::InventoryAction, rpc, CarbideCliError, CarbideCliResult};

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
    dpu_machine_id: String,
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

            machine_element.insert(
                hostname,
                HostMachineInfo {
                    ansible_host: address,
                    machine_id: machine.id.clone().unwrap_or_default().to_string(),
                    dpu_machine_id: primary_interface
                        .attached_dpu_machine_id
                        .clone()
                        .unwrap_or_default()
                        .to_string(),
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
                    machine_id: machine.id.clone().unwrap_or_default().to_string(),
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

    let managed_host_map: HashMap<String, String> = managed_hosts
        .iter()
        .map(|x| (x.dpu_bmc_ip.clone(), x.host_bmc_ip.clone()))
        .collect();

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
            format!("{}-bmc", hostname),
            BmcInfo {
                ansible_host: bmc_ip.clone(),
                host_bmc_ip: managed_host_map.get(&bmc_ip).cloned(),
            },
        );

        known_ips.push(bmc_ip);
    }

    for managed_host in managed_hosts {
        if !known_ips.contains(&managed_host.dpu_bmc_ip) {
            // Found a undiscovered dpu bmc ip.
            bmc_element.insert(
                format!("{}-undiscovered-bmc", managed_host.dpu_bmc_ip),
                BmcInfo {
                    ansible_host: managed_host.dpu_bmc_ip,
                    host_bmc_ip: Some(managed_host.host_bmc_ip),
                },
            );
        }
    }

    bmc_element
}

fn machine_type(machine_id: &Option<MachineId>) -> MachineType {
    let Some(machine_id) = machine_id else {
        return MachineType::Unknown;
    };

    match machine_id.id.as_bytes()[5] as char {
        'd' => MachineType::Dpu,
        'p' | 'h' => MachineType::Host,
        _ => MachineType::Unknown,
    }
}

/// Main entry function which print inventory.
pub async fn print_inventory(
    api_config: &ApiConfig<'_>,
    action: InventoryAction,
    page_size: usize,
) -> CarbideCliResult<()> {
    let all_machines = rpc::get_all_machines(api_config, None, false, page_size).await?;
    let all_instances = rpc::get_instances(api_config, None, None, None).await?;

    let (instances, used_machine) = create_inventory_for_instances(all_instances, &all_machines)?;

    let children: InstanceGroup = HashMap::from([(
        "children",
        HashMap::from_iter(instances.keys().map(|x| (x.clone(), None))),
    )]);

    let mut final_group: HashMap<String, TopYamlElement> = HashMap::from([(
        "instances".to_string(),
        TopYamlElement::InstanceChildren(children),
    )]);

    let site_report_managed_host = rpc::get_site_exploration_report(api_config)
        .await?
        .managed_hosts;

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
        .filter(|x| machine_type(&x.id) == MachineType::Host)
        .collect::<Vec<&::rpc::Machine>>();

    let all_dpus = all_machines
        .machines
        .iter()
        .filter(|x| machine_type(&x.id) == MachineType::Dpu)
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
        println!("{}", output);
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

/// Generate inventory item for instances.
#[allow(clippy::type_complexity)]
fn create_inventory_for_instances(
    instances: InstanceList,
    machines: &MachineList,
) -> CarbideCliResult<(
    HashMap<String, Vec<InstanceDetails>>,
    Vec<Option<::rpc::MachineId>>,
)> {
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

        used_machines.push(machine.id.clone());

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
