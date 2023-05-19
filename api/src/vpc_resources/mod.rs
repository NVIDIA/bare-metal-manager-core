/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::BTreeMap;
use std::time::SystemTime;

use chrono::DateTime;
use itertools::Itertools;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use crate::model::instance::config::network::InterfaceFunctionId;
use crate::model::machine::machine_id::MachineId;

pub mod configuration_resource_pool;
pub mod leaf;
pub mod managed_resource;
pub mod resource_group;

const DPU_PHYSICAL_NETWORK_INTERFACE: &str = "pf0hpf";
const DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER: &str = "pf0vf";

pub trait VpcResource {
    type Status: VpcResourceStatus;

    fn status(&self) -> Option<&Self::Status>;
    fn metadata(&self) -> &ObjectMeta;
    fn vpc_resource_name(&self) -> Option<&String> {
        self.metadata().name.as_ref()
    }
}

pub trait VpcResourceCondition {
    fn timestamp(&self) -> Option<&str>;
}

pub trait VpcResourceStatus {
    fn is_ready(&self) -> bool;
}

pub trait VpcResourceMetadata {
    fn name(&self) -> Option<&String>;
}

fn latest_condition<C: VpcResourceCondition>(conditions: &[C]) -> Option<&C> {
    let default_timestamp: &str = "0";

    conditions
        .iter()
        .sorted_by_key(|condition_to_be_sorted| {
            let time_stamp = condition_to_be_sorted
                .timestamp()
                .unwrap_or(default_timestamp);

            if let Ok(duration) = chrono::DateTime::parse_from_rfc3339(time_stamp) {
                duration
                    .signed_duration_since(DateTime::<chrono::Utc>::from(SystemTime::UNIX_EPOCH))
                    .num_milliseconds() as u64
            } else {
                0
            }
        })
        .last()
}

impl VpcResource for leaf::Leaf {
    type Status = leaf::LeafStatus;
    fn status(&self) -> Option<&Self::Status> {
        self.status.as_ref()
    }
    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl VpcResourceStatus for leaf::LeafStatus {
    fn is_ready(&self) -> bool {
        if let Some(conditions) = self.conditions.as_ref() {
            if let Some(condition) = latest_condition(conditions) {
                if let Some(condition_status) = condition.status.as_ref() {
                    if condition_status.to_lowercase().as_str() != "true" {
                        return false;
                    }

                    if let Some(host_admin_ips) = self.host_admin_i_ps.as_ref() {
                        return !host_admin_ips.is_empty();
                    }
                }
            }
        }
        false
    }
}

impl VpcResourceCondition for leaf::LeafStatusConditions {
    fn timestamp(&self) -> Option<&str> {
        self.last_transition_time.as_deref()
    }
}

impl VpcResource for resource_group::ResourceGroup {
    type Status = resource_group::ResourceGroupStatus;
    fn status(&self) -> Option<&Self::Status> {
        self.status.as_ref()
    }
    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl VpcResourceStatus for resource_group::ResourceGroupStatus {
    fn is_ready(&self) -> bool {
        if let Some(conditions) = self.conditions.as_ref() {
            if let Some(condition) = latest_condition(conditions) {
                if let Some(condition_status) = condition.status.as_ref() {
                    if condition_status.to_lowercase().as_str() != "true" {
                        return false;
                    }
                    return self.dhcp_circ_id.is_some();
                }
            }
        }
        false
    }
}

impl VpcResourceCondition for resource_group::ResourceGroupStatusConditions {
    fn timestamp(&self) -> Option<&str> {
        self.last_transition_time.as_deref()
    }
}

impl VpcResource for managed_resource::ManagedResource {
    type Status = managed_resource::ManagedResourceStatus;
    fn status(&self) -> Option<&Self::Status> {
        self.status.as_ref()
    }
    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl VpcResourceStatus for managed_resource::ManagedResourceStatus {
    fn is_ready(&self) -> bool {
        if let Some(conditions) = self.conditions.as_ref() {
            if let Some(condition) = latest_condition(conditions) {
                if let Some(condition_status) = condition.status.as_ref() {
                    return condition_status.to_lowercase().as_str() == "true";
                }
            }
        }
        false
    }
}

impl VpcResourceCondition for managed_resource::ManagedResourceStatusConditions {
    fn timestamp(&self) -> Option<&str> {
        self.last_transition_time.as_deref()
    }
}

pub struct BlueFieldInterface(InterfaceFunctionId);

impl BlueFieldInterface {
    pub fn new(interface: InterfaceFunctionId) -> Self {
        BlueFieldInterface(interface)
    }

    pub fn leaf_interface_id(&self, dpu_machine_id: &MachineId) -> String {
        format!("{}.{}", dpu_machine_id, self.0.kube_representation())
    }

    pub fn interface_name(&self) -> String {
        match self.0 {
            InterfaceFunctionId::Physical {} => DPU_PHYSICAL_NETWORK_INTERFACE.to_string(),
            InterfaceFunctionId::Virtual { id } => {
                format!("{}{}", DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER, id - 1)
            }
        }
    }
}

struct BlueFieldInterfaceMap {
    interfaces: BTreeMap<String, String>,
    dpu_machine_id: MachineId,
}

impl BlueFieldInterfaceMap {
    fn new(dpu_machine_id: MachineId) -> Self {
        BlueFieldInterfaceMap {
            interfaces: BTreeMap::new(),
            dpu_machine_id,
        }
    }

    fn insert(&mut self, interface: InterfaceFunctionId) {
        let bluefield_interface = BlueFieldInterface::new(interface);
        self.interfaces.insert(
            bluefield_interface.leaf_interface_id(&self.dpu_machine_id),
            bluefield_interface.interface_name(),
        );
    }
}

pub fn host_interfaces(dpu_machine_id: &MachineId) -> BTreeMap<String, String> {
    // Virtual interfaces start from 1 to 16.
    let mut interface_map = BlueFieldInterfaceMap::new(dpu_machine_id.to_owned());

    for function_id in InterfaceFunctionId::iter_all() {
        interface_map.insert(function_id);
    }

    interface_map.interfaces
}

#[cfg(test)]
mod tests {
    use ::rstest_reuse::*;
    use rstest::rstest;

    use super::*;

    const BASE_TIME: &str = "2022-09-29T16:40:49Z";
    const NEW_TIME: &str = "2022-09-29T18:40:49Z";
    const DPU_MACHINE_ID: &str = "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g";

    #[template]
    #[rstest]
    #[case(
        0,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.pf",
        "pf0hpf"
    )]
    #[case(
        1,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-1",
        "pf0vf0"
    )]
    #[case(
        2,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-2",
        "pf0vf1"
    )]
    #[case(
        3,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-3",
        "pf0vf2"
    )]
    #[case(
        4,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-4",
        "pf0vf3"
    )]
    #[case(
        5,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-5",
        "pf0vf4"
    )]
    #[case(
        6,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-6",
        "pf0vf5"
    )]
    #[case(
        7,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-7",
        "pf0vf6"
    )]
    #[case(
        8,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-8",
        "pf0vf7"
    )]
    #[case(
        9,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-9",
        "pf0vf8"
    )]
    #[case(
        10,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-10",
        "pf0vf9"
    )]
    #[case(
        11,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-11",
        "pf0vf10"
    )]
    #[case(
        12,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-12",
        "pf0vf11"
    )]
    #[case(
        13,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-13",
        "pf0vf12"
    )]
    #[case(
        14,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-14",
        "pf0vf13"
    )]
    #[case(
        15,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-15",
        "pf0vf14"
    )]
    #[case(
        16,
        "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.vf-16",
        "pf0vf15"
    )]
    fn test_params() {}

    #[apply(test_params)]
    fn test_host_interfaces(#[case] _id: u8, #[case] key: &str, #[case] value: &str) {
        let x = host_interfaces(&DPU_MACHINE_ID.parse().unwrap());
        let val = x.get(key);
        assert!(val.is_some());
        assert_eq!(val.unwrap(), value);
    }

    #[test]
    fn test_leaf_interface_id_physical() {
        let physical_interface = BlueFieldInterface::new(InterfaceFunctionId::Physical {});
        assert_eq!(
            "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g.pf".to_owned(),
            physical_interface.leaf_interface_id(&DPU_MACHINE_ID.parse().unwrap())
        );
    }

    #[apply(test_params)]
    fn test_leaf_interface_id_virtual(
        #[case] id: u8,
        #[case] leaf_interface_name: &str,
        #[case] interface_name: &str,
    ) {
        if id == 0 {
            return;
        }
        let virtual_interface = BlueFieldInterface::new(InterfaceFunctionId::Virtual { id });
        assert_eq!(
            leaf_interface_name,
            virtual_interface.leaf_interface_id(&DPU_MACHINE_ID.parse().unwrap())
        );
        assert_eq!(interface_name, virtual_interface.interface_name());
    }

    #[test]
    fn latest_condition_time_is_newest_timestamp() {
        let last_transition_time_1 = chrono::DateTime::parse_from_rfc3339(BASE_TIME)
            .expect("Unable to convert transition time");

        let last_transition_time_1 = last_transition_time_1
            .signed_duration_since(DateTime::<chrono::Utc>::from(SystemTime::UNIX_EPOCH))
            .num_milliseconds() as u64;

        let last_transition_time_2 = chrono::DateTime::parse_from_rfc3339(NEW_TIME)
            .expect("Unable to convert transition time");
        let last_transition_time_2 = last_transition_time_2
            .signed_duration_since(DateTime::<chrono::Utc>::from(SystemTime::UNIX_EPOCH))
            .num_milliseconds() as u64;

        let current_leaf_status_condition = leaf::LeafStatusConditions {
            last_transition_time: Some(last_transition_time_1.to_string()),
            message: Some(format!(
                "I'm a condition at time {}",
                last_transition_time_1
            )),
            status: Some("true".to_string()),
            r#type: Some("Liveness".to_string()),
        };

        let new_leaf_status_condition = leaf::LeafStatusConditions {
            last_transition_time: Some(last_transition_time_2.to_string()),
            message: Some(format!(
                "I am a condition at time {}",
                last_transition_time_2
            )),
            status: Some("true".to_string()),
            r#type: Some("Liveness".to_string()),
        };

        let conditions_array = vec![
            current_leaf_status_condition,
            new_leaf_status_condition.clone(),
        ];
        let res = latest_condition(&conditions_array);

        if let Some(result) = res {
            if let Some(last) = &result.last_transition_time {
                assert_eq!(
                    last.to_owned(),
                    new_leaf_status_condition.last_transition_time.unwrap()
                );
                if let Some(message) = &result.message {
                    assert_eq!(
                        message.to_owned(),
                        format!("I am a condition at time {}", last_transition_time_2)
                    )
                }
            }
        }
    }
}
