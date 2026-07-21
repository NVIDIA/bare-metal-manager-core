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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use carbide_authn::middleware::ConnectionAttributes;
use common::api_fixtures::dpu::create_dpu_machine;
use common::api_fixtures::host::{host_discover_dhcp, host_discover_machine_with_reporter};
use common::api_fixtures::{FIXTURE_DHCP_RELAY_ADDRESS, create_managed_host, create_test_env};
use itertools::Itertools;
use mac_address::MacAddress;
use model::hardware_info::{HardwareInfo, TpmEkCertificate};
use model::machine::machine_id::from_hardware_info;
use model::machine::machine_search_config::MachineSearchConfig;
use rpc::forge::forge_server::Forge;
use tonic::{Code, Request};

use crate::tests::common;
use crate::tests::common::api_fixtures::{TestEnvOverrides, create_test_env_with_overrides};

fn secure_discovery_config() -> crate::cfg::file::CarbideConfig {
    let mut config = common::api_fixtures::get_config();
    config.allow_insecure_discovery = false;
    config
}

#[crate::sqlx_test]
async fn test_machine_discovery_no_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let machine_interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        std::slice::from_ref(&FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap()),
        None,
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
        std::slice::from_ref(&FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap()),
        None,
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
            ..Default::default()
        }))
        .await;
    let err = response.expect_err("Expected DiscoverMachine request to fail");
    assert!(
        err.to_string()
            .contains("ignoring DiscoverMachine request for non-tpm enabled host")
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
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(secure_discovery_config()),
    )
    .await;
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
            address_family: None,
            message_kind: None,
            duid: None,
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
        ..Default::default()
    });

    let dhcp_address: IpAddr = dhcp_response.address.parse().unwrap();
    req.extensions_mut()
        .insert::<Arc<ConnectionAttributes>>(Arc::new(ConnectionAttributes {
            peer_address: SocketAddr::from((dhcp_address, 0)),
            peer_certificates: vec![],
        }));

    let response = env.api.discover_machine(req).await.unwrap().into_inner();

    assert!(response.machine_id.is_some());
    assert_eq!(
        response.machine_interface_id,
        dhcp_response.machine_interface_id
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_discover_dpu_not_create_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(secure_discovery_config()),
    )
    .await;
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
            address_family: None,
            message_kind: None,
            duid: None,
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
        ..Default::default()
    });

    let dhcp_address: IpAddr = dhcp_response.address.parse().unwrap();
    req.extensions_mut()
        .insert::<Arc<ConnectionAttributes>>(Arc::new(ConnectionAttributes {
            peer_address: SocketAddr::from((dhcp_address, 0)),
            peer_certificates: vec![],
        }));

    let response = env.api.discover_machine(req).await;

    assert_eq!(response.unwrap_err().code(), Code::PermissionDenied);

    Ok(())
}

#[crate::sqlx_test]
async fn test_discover_dpu_does_not_create_machine_when_site_explorer_creates_machines(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = secure_discovery_config();
    config
        .site_explorer
        .create_machines
        .store(true, Ordering::Relaxed);
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;
    let dpu = env
        .managed_host_config()
        .get_and_assert_single_dpu()
        .clone();
    let expected_machine_id = from_hardware_info(&HardwareInfo::from(&dpu))?;

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
            address_family: None,
            message_kind: None,
            duid: None,
        }))
        .await?
        .into_inner();

    let remote_ip: IpAddr = dhcp_response.address.parse()?;
    let mut request = Request::new(rpc::MachineDiscoveryInfo {
        machine_interface_id: None,
        discovery_data: Some(rpc::DiscoveryData::Info(rpc::DiscoveryInfo::try_from(
            HardwareInfo::from(&dpu),
        )?)),
        create_machine: true,
        ..Default::default()
    });
    request
        .extensions_mut()
        .insert::<Arc<ConnectionAttributes>>(Arc::new(ConnectionAttributes {
            peer_address: SocketAddr::from((remote_ip, 0)),
            peer_certificates: vec![],
        }));

    let response = env.api.discover_machine(request).await;

    assert_eq!(response.unwrap_err().code(), Code::PermissionDenied);
    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::find_one(
        &mut *txn,
        dhcp_response
            .machine_interface_id
            .expect("DHCP discovery must return an interface ID"),
    )
    .await?;
    assert_eq!(interface.machine_id, None);
    assert!(
        db::machine::find_one(
            &mut *txn,
            &expected_machine_id,
            MachineSearchConfig {
                include_dpus: true,
                ..Default::default()
            },
        )
        .await?
        .is_none()
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_secure_discovery_requires_remote_ip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(secure_discovery_config()),
    )
    .await;
    let dpu = env
        .managed_host_config()
        .get_and_assert_single_dpu()
        .clone();
    let interface_id =
        common::api_fixtures::dpu::dpu_discover_dhcp(&env, &dpu.oob_mac_address.to_string()).await;

    let response = env
        .api
        .discover_machine(Request::new(rpc::MachineDiscoveryInfo {
            machine_interface_id: Some(interface_id),
            discovery_data: Some(rpc::DiscoveryData::Info(
                rpc::DiscoveryInfo::try_from(HardwareInfo::from(&dpu)).unwrap(),
            )),
            create_machine: true,
            ..Default::default()
        }))
        .await;

    assert_eq!(response.unwrap_err().code(), Code::InvalidArgument);
    Ok(())
}

#[crate::sqlx_test]
async fn test_secure_discovery_does_not_fall_back_to_interface_id(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(secure_discovery_config()),
    )
    .await;
    let dpu = env
        .managed_host_config()
        .get_and_assert_single_dpu()
        .clone();
    let interface_id =
        common::api_fixtures::dpu::dpu_discover_dhcp(&env, &dpu.oob_mac_address.to_string()).await;
    let mut request = Request::new(rpc::MachineDiscoveryInfo {
        machine_interface_id: Some(interface_id),
        discovery_data: Some(rpc::DiscoveryData::Info(
            rpc::DiscoveryInfo::try_from(HardwareInfo::from(&dpu)).unwrap(),
        )),
        create_machine: true,
        ..Default::default()
    });

    request
        .extensions_mut()
        .insert::<Arc<ConnectionAttributes>>(Arc::new(ConnectionAttributes {
            peer_address: SocketAddr::from((Ipv4Addr::new(203, 0, 113, 252), 0)),
            peer_certificates: vec![],
        }));

    let response = env.api.discover_machine(request).await;

    assert_eq!(response.unwrap_err().code(), Code::NotFound);
    Ok(())
}

#[crate::sqlx_test]
async fn test_secure_discovery_promotes_predicted_host_by_remote_ip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(secure_discovery_config()),
    )
    .await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;
    let host_interface_id = host_discover_dhcp(&env, &host_config, &dpu_machine_id).await;
    let mut txn = env.pool.begin().await?;
    let host_interface = db::machine_interface::find_one(&mut *txn, host_interface_id).await?;
    txn.commit().await?;
    let remote_ip = host_interface.addresses[0];
    let expected_machine_id = from_hardware_info(&HardwareInfo::from(&host_config))?;
    let mut request = Request::new(rpc::MachineDiscoveryInfo {
        machine_interface_id: Some(uuid::Uuid::new_v4().into()),
        discovery_data: Some(rpc::DiscoveryData::Info(
            rpc::DiscoveryInfo::try_from(HardwareInfo::from(&host_config)).unwrap(),
        )),
        create_machine: true,
        ..Default::default()
    });

    request
        .extensions_mut()
        .insert::<Arc<ConnectionAttributes>>(Arc::new(ConnectionAttributes {
            peer_address: SocketAddr::from((remote_ip, 0)),
            peer_certificates: vec![],
        }));

    let response = env.api.discover_machine(request).await?.into_inner();

    assert_eq!(response.machine_id, Some(expected_machine_id));
    assert_eq!(response.machine_interface_id, Some(host_interface_id));
    Ok(())
}

#[crate::sqlx_test]
async fn test_secure_discovery_rejects_stable_host_identity_mismatch_without_mutation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(secure_discovery_config()),
    )
    .await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;
    let host_interface_id = host_discover_dhcp(&env, &host_config, &dpu_machine_id).await;
    let mut txn = env.pool.begin().await?;
    let host_interface = db::machine_interface::find_one(&mut *txn, host_interface_id).await?;
    txn.commit().await?;
    let remote_ip = host_interface.addresses[0];
    let expected_machine_id = from_hardware_info(&HardwareInfo::from(&host_config))?;

    let mut initial_request = Request::new(rpc::MachineDiscoveryInfo {
        machine_interface_id: None,
        discovery_data: Some(rpc::DiscoveryData::Info(rpc::DiscoveryInfo::try_from(
            HardwareInfo::from(&host_config),
        )?)),
        create_machine: true,
        ..Default::default()
    });
    initial_request
        .extensions_mut()
        .insert::<Arc<ConnectionAttributes>>(Arc::new(ConnectionAttributes {
            peer_address: SocketAddr::from((remote_ip, 0)),
            peer_certificates: vec![],
        }));
    let initial_response = env
        .api
        .discover_machine(initial_request)
        .await?
        .into_inner();
    assert_eq!(initial_response.machine_id, Some(expected_machine_id));

    let mut mismatching_hardware = HardwareInfo::from(&host_config);
    mismatching_hardware.tpm_ek_certificate = Some(TpmEkCertificate::from(vec![0x5a; 512]));
    let mismatching_machine_id = from_hardware_info(&mismatching_hardware)?;
    assert_ne!(mismatching_machine_id, expected_machine_id);
    let mut mismatching_request = Request::new(rpc::MachineDiscoveryInfo {
        machine_interface_id: None,
        discovery_data: Some(rpc::DiscoveryData::Info(rpc::DiscoveryInfo::try_from(
            mismatching_hardware,
        )?)),
        create_machine: true,
        ..Default::default()
    });
    mismatching_request
        .extensions_mut()
        .insert::<Arc<ConnectionAttributes>>(Arc::new(ConnectionAttributes {
            peer_address: SocketAddr::from((remote_ip, 0)),
            peer_certificates: vec![],
        }));

    let response = env.api.discover_machine(mismatching_request).await;

    assert_eq!(response.unwrap_err().code(), Code::PermissionDenied);
    let mut txn = env.pool.begin().await?;
    let host_interface = db::machine_interface::find_one(&mut *txn, host_interface_id).await?;
    assert_eq!(host_interface.machine_id, Some(expected_machine_id));
    let topology_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM machine_topologies WHERE machine_id = $1")
            .bind(mismatching_machine_id)
            .fetch_one(&mut *txn)
            .await?;
    assert_eq!(topology_count.0, 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_insecure_discovery_uses_interface_id_and_ignores_remote_ip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let dpu = env
        .managed_host_config()
        .get_and_assert_single_dpu()
        .clone();
    let interface_id =
        common::api_fixtures::dpu::dpu_discover_dhcp(&env, &dpu.oob_mac_address.to_string()).await;
    let mut request = Request::new(rpc::MachineDiscoveryInfo {
        machine_interface_id: Some(interface_id),
        discovery_data: Some(rpc::DiscoveryData::Info(
            rpc::DiscoveryInfo::try_from(HardwareInfo::from(&dpu)).unwrap(),
        )),
        create_machine: true,
        ..Default::default()
    });
    request
        .extensions_mut()
        .insert::<Arc<ConnectionAttributes>>(Arc::new(ConnectionAttributes {
            peer_address: SocketAddr::from((Ipv4Addr::new(203, 0, 113, 254), 0)),
            peer_certificates: vec![],
        }));

    let response = env.api.discover_machine(request).await?.into_inner();

    assert_eq!(response.machine_interface_id, Some(interface_id));
    Ok(())
}

#[crate::sqlx_test]
async fn test_insecure_discovery_requires_interface_id(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let dpu = env
        .managed_host_config()
        .get_and_assert_single_dpu()
        .clone();
    let response = env
        .api
        .discover_machine(Request::new(rpc::MachineDiscoveryInfo {
            machine_interface_id: None,
            discovery_data: Some(rpc::DiscoveryData::Info(
                rpc::DiscoveryInfo::try_from(HardwareInfo::from(&dpu)).unwrap(),
            )),
            create_machine: true,
            ..Default::default()
        }))
        .await;

    assert_eq!(response.unwrap_err().code(), Code::InvalidArgument);
    Ok(())
}

#[crate::sqlx_test]
async fn test_discovery_ip_lookup_rejects_missing_and_ambiguous_mappings(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let first_interface_id =
        common::api_fixtures::dpu::dpu_discover_dhcp(&env, "02:00:00:00:10:01").await;
    let second_interface_id =
        common::api_fixtures::dpu::dpu_discover_dhcp(&env, "02:00:00:00:10:02").await;

    let mut txn = env.pool.begin().await?;
    let missing =
        db::machine_interface::find_for_update_by_ip(&mut txn, "203.0.113.253".parse().unwrap())
            .await;
    assert!(missing.is_err());

    let first_interface = db::machine_interface::find_one(&mut *txn, first_interface_id).await?;
    let first_address = first_interface.addresses[0];
    sqlx::query("UPDATE machine_interface_addresses SET address = $1 WHERE interface_id = $2")
        .bind(first_address)
        .bind(second_interface_id)
        .execute(&mut *txn)
        .await?;

    let ambiguous = db::machine_interface::find_for_update_by_ip(&mut txn, first_address).await;
    assert!(ambiguous.is_err());
    Ok(())
}

#[crate::sqlx_test]
async fn test_discovery_rejects_interface_owned_by_different_stable_identity(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let dpu = env
        .managed_host_config()
        .get_and_assert_single_dpu()
        .clone();
    let interface_id =
        common::api_fixtures::dpu::dpu_discover_dhcp(&env, &dpu.oob_mac_address.to_string()).await;
    let first_hardware = HardwareInfo::from(&dpu);
    let first_machine_id =
        common::api_fixtures::dpu::dpu_discover_machine(&env, &dpu, interface_id).await;

    let mut other_hardware = first_hardware;
    other_hardware
        .dmi_data
        .as_mut()
        .expect("DPU fixture must contain DMI data")
        .product_serial
        .push_str("-different");
    let other_machine_id = from_hardware_info(&other_hardware)?;
    assert_ne!(first_machine_id, other_machine_id);

    let response = env
        .api
        .discover_machine(Request::new(rpc::MachineDiscoveryInfo {
            machine_interface_id: Some(interface_id),
            discovery_data: Some(rpc::DiscoveryData::Info(
                rpc::DiscoveryInfo::try_from(other_hardware).unwrap(),
            )),
            create_machine: true,
            ..Default::default()
        }))
        .await;

    assert_eq!(response.unwrap_err().code(), Code::PermissionDenied);
    let topology_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM machine_topologies WHERE machine_id = $1")
            .bind(other_machine_id)
            .fetch_one(&env.pool)
            .await?;
    assert_eq!(topology_count.0, 0);
    Ok(())
}

/// A Scout-reported discovery records the reporter version on the machine and
/// persists it in the database.
#[crate::sqlx_test]
async fn test_discovery_records_scout_version(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;
    let host_machine_interface_id = host_discover_dhcp(&env, &host_config, &dpu_machine_id).await;

    let machine_id = host_discover_machine_with_reporter(
        &env,
        &host_config,
        host_machine_interface_id,
        rpc::MachineDiscoveryReporter::Scout,
        Some("v0.11.0-pr-11-g14586866e"),
    )
    .await;

    // The version is exposed on the Machine resource over gRPC.
    let rpc_machine = env
        .api
        .find_machines_by_ids(Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![machine_id],
            include_history: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);
    assert_eq!(
        rpc_machine
            .status
            .as_ref()
            .unwrap()
            .last_scout_observed_version
            .as_deref(),
        Some("v0.11.0-pr-11-g14586866e")
    );

    Ok(())
}

/// A version reported by the DPU agent (rather than Scout) is not recorded as
/// the last seen Scout version.
#[crate::sqlx_test]
async fn test_discovery_ignores_version_from_dpu_agent(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;
    let host_machine_interface_id = host_discover_dhcp(&env, &host_config, &dpu_machine_id).await;

    let machine_id = host_discover_machine_with_reporter(
        &env,
        &host_config,
        host_machine_interface_id,
        rpc::MachineDiscoveryReporter::DpuAgent,
        Some("v0.11.0-pr-11-g14586866e"),
    )
    .await;

    let machine = db::machine::find_one(&env.pool, &machine_id, MachineSearchConfig::default())
        .await?
        .expect("machine must exist");

    assert!(machine.status.last_scout_observed_version.is_none());

    Ok(())
}

/// A subsequent Scout discovery overwrites the previously recorded version.
#[crate::sqlx_test]
async fn test_discovery_updates_scout_version_on_rediscovery(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;
    let host_machine_interface_id = host_discover_dhcp(&env, &host_config, &dpu_machine_id).await;

    let machine_id = host_discover_machine_with_reporter(
        &env,
        &host_config,
        host_machine_interface_id,
        rpc::MachineDiscoveryReporter::Scout,
        Some("v0.11.0-pr-11-g14586866e"),
    )
    .await;
    let machine = db::machine::find_one(&env.pool, &machine_id, MachineSearchConfig::default())
        .await?
        .expect("machine must exist");
    assert_eq!(
        machine.status.last_scout_observed_version.as_deref(),
        Some("v0.11.0-pr-11-g14586866e")
    );
    let rediscovered_machine_id = host_discover_machine_with_reporter(
        &env,
        &host_config,
        host_machine_interface_id,
        rpc::MachineDiscoveryReporter::Scout,
        Some("v0.12.0-pr-42-gabcdef012"),
    )
    .await;
    assert_eq!(rediscovered_machine_id, machine_id);
    let machine = db::machine::find_one(&env.pool, &machine_id, MachineSearchConfig::default())
        .await?
        .expect("machine must exist");
    assert_eq!(
        machine.status.last_scout_observed_version.as_deref(),
        Some("v0.12.0-pr-42-gabcdef012")
    );

    Ok(())
}
