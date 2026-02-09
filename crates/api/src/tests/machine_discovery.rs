/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::net::IpAddr;
use std::str::FromStr;

use common::api_fixtures::dpu::create_dpu_machine;
use common::api_fixtures::host::host_discover_dhcp;
use common::api_fixtures::{FIXTURE_DHCP_RELAY_ADDRESS, create_managed_host, create_test_env};
use itertools::Itertools;
use mac_address::MacAddress;
use model::hardware_info::HardwareInfo;
use rpc::forge::forge_server::Forge;
use tonic::Request;

use crate::tests::common;

#[crate::sqlx_test]
async fn test_machine_discovery_no_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let machine_interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap(),
        None,
    )
    .await
    .expect("Unable to create machine");

    let wanted_ips: Vec<IpAddr> = vec!["192.0.2.3".parse().unwrap()]
        .into_iter()
        .sorted()
        .collect::<Vec<IpAddr>>();

    let actual_ips = machine_interface
        .addresses
        .iter()
        .copied()
        .sorted()
        .collect::<Vec<IpAddr>>();

    assert_eq!(actual_ips, wanted_ips);

    Ok(())
}

#[crate::sqlx_test]
async fn test_machine_discovery_with_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let machine_interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap(),
        None,
    )
    .await
    .expect("Unable to create machine");

    let wanted_ips: Vec<IpAddr> = vec!["192.0.2.3".parse().unwrap()];

    assert_eq!(
        machine_interface
            .addresses
            .iter()
            .copied()
            .sorted()
            .collect::<Vec<IpAddr>>(),
        wanted_ips.into_iter().sorted().collect::<Vec<IpAddr>>()
    );

    assert!(
        machine_interface
            .addresses
            .iter()
            .any(|item| *item == "192.0.2.3".parse::<IpAddr>().unwrap())
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_reject_host_machine_with_disabled_tpm(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;

    let host_machine_interface_id = host_discover_dhcp(&env, &host_config, &dpu_machine_id).await;

    let mut hardware_info = HardwareInfo::from(&host_config);
    hardware_info.tpm_ek_certificate = None;

    let response = env
        .api
        .discover_machine(tonic::Request::new(rpc::MachineDiscoveryInfo {
            machine_interface_id: Some(host_machine_interface_id),
            discovery_data: Some(rpc::DiscoveryData::Info(
                rpc::DiscoveryInfo::try_from(hardware_info).unwrap(),
            )),
            create_machine: true,
        }))
        .await;
    let err = response.expect_err("Expected DiscoverMachine request to fail");
    assert!(
        err.to_string()
            .contains("Ignoring DiscoverMachine request for non-tpm enabled host")
    );

    // We shouldn't have created any machine
    let machine_ids = env
        .api
        .find_machine_ids(tonic::Request::new(
            rpc::forge::MachineSearchConfig::default(),
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(machine_ids.machine_ids.is_empty());

    Ok(())
}

#[crate::sqlx_test]
async fn test_discover_2_managed_hosts(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env: common::api_fixtures::TestEnv = create_test_env(pool).await;
    let (host1_id, dpu1_id) = create_managed_host(&env).await.into();
    let (host2_id, dpu2_id) = create_managed_host(&env).await.into();
    assert!(host1_id.machine_type().is_host());
    assert!(host2_id.machine_type().is_host());
    assert!(dpu1_id.machine_type().is_dpu());
    assert!(dpu2_id.machine_type().is_dpu());
    assert_ne!(host1_id, host2_id);
    assert_ne!(dpu1_id, dpu2_id);

    let machine_ids = env
        .api
        .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
            include_dpus: true,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machine_ids;
    assert_eq!(machine_ids.len(), 4);

    Ok(())
}

#[crate::sqlx_test]
async fn test_discover_dpu_by_source_ip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu = host_config.get_and_assert_single_dpu();

    let dhcp_response = env
        .api
        .discover_dhcp(Request::new(rpc::forge::DhcpDiscovery {
            mac_address: dpu.oob_mac_address.to_string(),
            relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
            vendor_string: None,
            link_address: None,
            circuit_id: None,
            remote_id: None,
            desired_address: None,
        }))
        .await
        .unwrap()
        .into_inner();

    let mut req = Request::new(rpc::MachineDiscoveryInfo {
        machine_interface_id: None,
        discovery_data: Some(rpc::DiscoveryData::Info(
            rpc::DiscoveryInfo::try_from(HardwareInfo::from(dpu)).unwrap(),
        )),
        create_machine: true,
    });
    req.metadata_mut()
        .insert("x-forwarded-for", dhcp_response.address.parse().unwrap());
    let response = env.api.discover_machine(req).await.unwrap().into_inner();

    assert!(response.machine_id.is_some());

    Ok(())
}

#[crate::sqlx_test]
async fn test_discover_dpu_not_create_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu = host_config.get_and_assert_single_dpu();

    let dhcp_response = env
        .api
        .discover_dhcp(Request::new(rpc::forge::DhcpDiscovery {
            mac_address: dpu.oob_mac_address.to_string(),
            relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
            vendor_string: None,
            link_address: None,
            circuit_id: None,
            remote_id: None,
            desired_address: None,
        }))
        .await
        .unwrap()
        .into_inner();

    let mut req = Request::new(rpc::MachineDiscoveryInfo {
        machine_interface_id: None,
        discovery_data: Some(rpc::DiscoveryData::Info(
            rpc::DiscoveryInfo::try_from(HardwareInfo::from(dpu)).unwrap(),
        )),
        create_machine: false,
    });
    req.metadata_mut()
        .insert("x-forwarded-for", dhcp_response.address.parse().unwrap());
    let response = env.api.discover_machine(req).await;

    assert!(response.is_err());

    Ok(())
}
