/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::{HashMap, HashSet};

use crate::cfg::file::IBFabricConfig;
use crate::tests::common;
use crate::tests::common::api_fixtures::TestEnvOverrides;
use common::api_fixtures::create_managed_host;
use forge_uuid::machine::MachineId;

#[crate::sqlx_test]
async fn machine_reports_ib_status(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        mtu: crate::ib::IBMtu(2),
        rate_limit: crate::ib::IBRateLimit(10),
        max_partition_per_tenant: 16,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    // Ingest 2 Machines. They should have different GUIDs, different LIDs, and report different IB status
    let (host_machine_id_1, _dpu_machine_id) = create_managed_host(&env).await;
    let (host_machine_id_2, _dpu_machine_id) = create_managed_host(&env).await;

    let host_machines = [host_machine_id_1, host_machine_id_2];
    let mut guids: HashMap<MachineId, Vec<String>> = HashMap::new();

    let mut active_lids = HashSet::new();

    for host_machine_id in host_machines.iter().cloned() {
        println!("Testing host machine {host_machine_id}");
        let rpc_machine_id: ::rpc::common::MachineId = host_machine_id.into();

        let machine = env
            .find_machines(Some(rpc_machine_id.clone()), None, false)
            .await
            .machines
            .remove(0);

        let machine_guids = guids.entry(host_machine_id_1).or_default();

        let discovery_info = machine.discovery_info.as_ref().unwrap();
        let ib_status = machine.ib_status.expect("IB status is missing");
        assert_eq!(
            discovery_info.infiniband_interfaces.len(),
            ib_status.ib_interfaces.len()
        );

        for ib_iface in discovery_info.infiniband_interfaces.iter() {
            machine_guids.push(ib_iface.guid.clone());
            let iface_status = ib_status
                .ib_interfaces
                .iter()
                .find(|iface| iface.guid() == ib_iface.guid)
                .expect("IB interface with matching GUID was not found");
            assert!(iface_status.lid.is_some());
            assert_ne!(iface_status.lid(), 0xffff_u32);
            assert!(
                !active_lids.contains(&iface_status.lid()),
                "Lid {} is used by multiple interfaces",
                iface_status.lid()
            );
            active_lids.insert(iface_status.lid());
        }

        assert_ne!(ib_status.ib_interfaces.len(), 0);
    }

    // Down the first and third interface of host_machine_1 and check
    // whether this gets reflected in the observed status
    let guid1 = guids.get(&host_machine_id_1).unwrap()[0].clone();
    let guid3 = guids.get(&host_machine_id_1).unwrap()[0].clone();
    env.ib_fabric_manager
        .get_mock_manager()
        .set_port_state(&guid1, false);
    env.ib_fabric_manager
        .get_mock_manager()
        .set_port_state(&guid3, false);

    env.run_machine_state_controller_iteration().await;

    active_lids.clear();
    for host_machine_id in host_machines.iter().cloned() {
        println!("Testing host machine {host_machine_id}");
        let rpc_machine_id: ::rpc::common::MachineId = host_machine_id.into();

        let machine = env
            .find_machines(Some(rpc_machine_id.clone()), None, false)
            .await
            .machines
            .remove(0);

        let discovery_info = machine.discovery_info.as_ref().unwrap();
        let ib_status = machine.ib_status.expect("IB status is missing");
        assert_eq!(
            discovery_info.infiniband_interfaces.len(),
            ib_status.ib_interfaces.len()
        );

        for ib_iface in discovery_info.infiniband_interfaces.iter() {
            let iface_status = ib_status
                .ib_interfaces
                .iter()
                .find(|iface| iface.guid() == ib_iface.guid)
                .expect("IB interface with matching GUID was not found");
            assert!(iface_status.lid.is_some());
            if ib_iface.guid == guid1 || ib_iface.guid == guid3 {
                assert_eq!(iface_status.lid(), 0xffff_u32);
            } else {
                assert_ne!(iface_status.lid(), 0xffff_u32);
                assert!(
                    !active_lids.contains(&iface_status.lid()),
                    "Lid {} is used by multiple interfaces",
                    iface_status.lid()
                );
                active_lids.insert(iface_status.lid());
            }
        }

        assert_ne!(ib_status.ib_interfaces.len(), 0);
    }
}
