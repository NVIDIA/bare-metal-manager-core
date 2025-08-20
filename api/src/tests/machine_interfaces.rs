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

use std::{borrow::Borrow, collections::HashSet, str::FromStr};

use crate::{
    CarbideError,
    db::{
        self,
        address_selection_strategy::AddressSelectionStrategy,
        dhcp_entry::DhcpEntry,
        domain::{self, Domain},
        network_segment::NetworkSegment,
    },
    model::machine::{
        MachineInterfaceSnapshot,
        machine_id::{from_hardware_info, try_parse_machine_id},
    },
};

use itertools::Itertools;
use mac_address::MacAddress;
use rpc::forge::{InterfaceSearchQuery, forge_server::Forge};

use crate::db::ObjectColumnFilter;
use crate::tests::common;
use crate::tests::common::api_fixtures::dpu::create_dpu_machine;
use common::api_fixtures::{FIXTURE_DHCP_RELAY_ADDRESS, create_test_env};
use tokio::sync::broadcast;
use tonic::Code;

#[crate::sqlx_test]
async fn only_one_primary_interface_per_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu = host_config.get_and_assert_single_dpu();
    let other_host_config = env.managed_host_config();
    let other_dpu = other_host_config.get_and_assert_single_dpu();

    let mut txn = env.pool.begin().await?;

    let network_segment = NetworkSegment::admin(&mut txn).await?;

    let new_interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &dpu.oob_mac_address,
        None,
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let machine_id = from_hardware_info(&host_config.borrow().into()).unwrap();
    let new_machine = db::machine::get_or_create(&mut txn, None, &machine_id, &new_interface)
        .await
        .expect("Unable to create machine");

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await?;

    let should_failed_machine_interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &other_dpu.oob_mac_address,
        None,
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let output = db::machine_interface::associate_interface_with_machine(
        &should_failed_machine_interface.id,
        &new_machine.id,
        &mut txn,
    )
    .await;

    txn.commit().await.unwrap();

    assert!(matches!(output, Err(CarbideError::OnePrimaryInterface)));

    Ok(())
}

#[crate::sqlx_test]
async fn many_non_primary_interfaces_per_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;
    let network_segment = NetworkSegment::admin(&mut txn).await?;

    db::machine_interface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create machine interface");

    txn.commit().await.unwrap();
    let mut txn = env.pool.begin().await?;

    let should_be_ok_interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ef").as_ref().unwrap(),
        None,
        false,
        AddressSelectionStrategy::Automatic,
    )
    .await;

    txn.commit().await.unwrap();

    assert!(should_be_ok_interface.is_ok());

    Ok(())
}

#[crate::sqlx_test]
async fn return_existing_machine_interface_on_rediscover(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: This tests only DHCP without Machines. For Interfaces with a Machine,
    // there are tests in `machine_dhcp.rs`
    // This should also be migrated to use actual API calls
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_machine = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        test_mac,
        FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap(),
    )
    .await?;

    let existing_machine = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        test_mac,
        FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap(),
    )
    .await?;

    assert_eq!(new_machine.id, existing_machine.id);

    Ok(())
}

#[crate::sqlx_test]
async fn find_all_interfaces_test_cases(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut txn = env.pool.begin().await?;

    let network_segment = NetworkSegment::admin(&mut txn).await?;
    let domain_ids = Domain::find_by(&mut txn, ObjectColumnFilter::<domain::IdColumn>::All).await?;
    let domain_id = domain_ids[0].id;
    let mut interfaces: Vec<MachineInterfaceSnapshot> = Vec::new();
    for i in 0..2 {
        let mut txn = env.pool.begin().await?;
        let interface = db::machine_interface::create(
            &mut txn,
            &network_segment,
            MacAddress::from_str(format!("ff:ff:ff:ff:ff:0{i}").as_str())
                .as_ref()
                .unwrap(),
            Some(domain_id),
            true,
            AddressSelectionStrategy::Automatic,
        )
        .await?;
        DhcpEntry {
            machine_interface_id: interface.id,
            vendor_string: format!("NVIDIA {i} 1"),
        }
        .persist(&mut txn)
        .await?;
        DhcpEntry {
            machine_interface_id: interface.id,
            vendor_string: format!("NVIDIA {i} 2"),
        }
        .persist(&mut txn)
        .await?;
        interfaces.push(interface);
        txn.commit().await.unwrap();
    }

    let response = env
        .api
        .find_interfaces(tonic::Request::new(InterfaceSearchQuery {
            id: None,
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();
    // Assert members
    for (idx, interface) in interfaces.into_iter().enumerate().take(2) {
        assert_eq!(response.interfaces[idx].hostname, interface.hostname);
        assert_eq!(
            response.interfaces[idx].mac_address,
            interface.mac_address.to_string()
        );
        // The newer vendor wins
        assert_eq!(
            response.interfaces[idx].vendor.clone().unwrap().to_string(),
            format!("NVIDIA {idx} 2")
        );
        assert_eq!(
            response.interfaces[idx]
                .domain_id
                .as_ref()
                .unwrap()
                .to_string(),
            interface.domain_id.unwrap().to_string()
        );
    }
    Ok(())
}

#[crate::sqlx_test]
async fn find_interfaces_test_cases(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu = host_config.get_and_assert_single_dpu();

    let mut txn = env.pool.begin().await?;

    let network_segment = NetworkSegment::admin(&mut txn).await?;
    let domain_ids = Domain::find_by(&mut txn, ObjectColumnFilter::<domain::IdColumn>::All).await?;
    let domain_id = domain_ids[0].id;
    let new_interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &dpu.oob_mac_address,
        Some(domain_id),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    DhcpEntry {
        machine_interface_id: new_interface.id,
        vendor_string: "NVIDIA".to_string(),
    }
    .persist(&mut txn)
    .await?;
    DhcpEntry {
        machine_interface_id: new_interface.id,
        vendor_string: "NVIDIA New".to_string(),
    }
    .persist(&mut txn)
    .await?;
    txn.commit().await?;

    let response = env
        .api
        .find_interfaces(tonic::Request::new(InterfaceSearchQuery {
            id: Some(new_interface.id.into()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();
    // Assert members
    // For new_interface
    assert_eq!(response.interfaces[0].hostname, new_interface.hostname);
    assert_eq!(
        response.interfaces[0].mac_address,
        new_interface.mac_address.to_string()
    );
    assert_eq!(
        response.interfaces[0].vendor.clone().unwrap(),
        "NVIDIA New".to_string()
    );
    assert_eq!(
        response.interfaces[0]
            .domain_id
            .as_ref()
            .unwrap()
            .to_string(),
        new_interface.domain_id.unwrap().to_string()
    );

    Ok(())
}

#[crate::sqlx_test]
async fn create_parallel_mi(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;
    let network = NetworkSegment::admin(&mut txn).await?;
    txn.commit().await.unwrap();

    let (tx, _rx1) = broadcast::channel(10);
    let max_interfaces = 250;
    let mut handles = vec![];
    for i in 0..max_interfaces {
        let n = network.clone();
        let mac = format!("ff:ff:ff:ff:{:02}:{:02}", i / 100, i % 100);
        let db_pool = env.pool.clone();
        let mut rx = tx.subscribe();
        let h = tokio::spawn(async move {
            // Let's start all threads together.
            _ = rx.recv().await.unwrap();
            let mut txn = db_pool.begin().await.unwrap();
            db::machine_interface::create(
                &mut txn,
                &n,
                &MacAddress::from_str(&mac).unwrap(),
                Some(env.domain.into()),
                true,
                AddressSelectionStrategy::Automatic,
            )
            .await
            .unwrap();

            // This call must pass. inner_txn is an illusion. Lock is still alive.
            _ = db::machine_interface::find_all(&mut txn).await.unwrap();
            txn.commit().await.unwrap();
        });
        handles.push(h);
    }

    tx.send(10).unwrap();

    for h in handles {
        _ = h.await;
    }
    let mut txn = env.pool.begin().await?;
    let interfaces = db::machine_interface::find_all(&mut txn).await.unwrap();

    assert_eq!(interfaces.len(), max_interfaces);
    let ips = interfaces
        .iter()
        .map(|x| x.addresses[0].to_string())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect_vec();
    assert_eq!(interfaces.len(), ips.len());

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_by_ip_or_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let network_segment = NetworkSegment::admin(&mut txn).await?;
    let interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        Some(env.domain.into()),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .unwrap();

    // By remote IP
    let remote_ip = Some(interface.addresses[0]);
    let interface_id = None;
    let iface = db::machine_interface::find_by_ip_or_id(&mut txn, remote_ip, interface_id).await?;
    assert_eq!(iface.id, interface.id);

    // By interface ID
    let remote_ip = None;
    let interface_id = Some(iface.id);
    let iface = db::machine_interface::find_by_ip_or_id(&mut txn, remote_ip, interface_id).await?;
    assert_eq!(iface.id, interface.id);

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete_interface(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let dhcp_response = env
        .api
        .discover_dhcp(tonic::Request::new(rpc::forge::DhcpDiscovery {
            mac_address: "FF:FF:FF:FF:FF:AA".to_string(),
            relay_address: "192.0.2.1".to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();

    let last_invalidation_time = dhcp_response
        .last_invalidation_time
        .expect("Last invalidation time should be set");

    // Find the Machine Interface ID for our new record
    let interface = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: None,
            ip: Some(dhcp_response.address.clone()),
        }))
        .await
        .unwrap()
        .into_inner()
        .interfaces
        .remove(0);
    let interface_id = interface.id.clone().unwrap();

    env.api
        .delete_interface(tonic::Request::new(rpc::forge::InterfaceDeleteQuery {
            id: Some(rpc::Uuid {
                value: interface_id.to_string(),
            }),
        }))
        .await
        .unwrap();

    let mut txn = env.pool.begin().await?;
    let _interface =
        db::machine_interface::find_one(&mut txn, interface_id.clone().try_into().unwrap()).await;
    assert!(matches!(
        CarbideError::FindOneReturnedNoResultsError(interface_id.clone().try_into().unwrap()),
        _interface
    ));

    txn.commit().await?;

    // The next discover_dhcp should return an updated timestamp
    let dhcp_response = env
        .api
        .discover_dhcp(tonic::Request::new(rpc::forge::DhcpDiscovery {
            mac_address: "FF:FF:FF:FF:FF:AA".to_string(),
            relay_address: "192.0.2.1".to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let new_invalidation_time = dhcp_response
        .last_invalidation_time
        .expect("Last invalidation time should be set");
    assert!(new_invalidation_time > last_invalidation_time);

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete_interface_with_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host_config = env.managed_host_config();
    let rpc_machine_id = create_dpu_machine(&env, &host_config).await;
    let dpu_machine_id = try_parse_machine_id(&rpc_machine_id).unwrap();

    let mut txn = pool.begin().await?;
    let interface = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id])
        .await
        .unwrap();

    let interface = &interface.get(&dpu_machine_id).unwrap()[0];
    txn.commit().await.unwrap();

    let response = env
        .api
        .delete_interface(tonic::Request::new(rpc::forge::InterfaceDeleteQuery {
            id: Some(rpc::Uuid {
                value: interface.id.to_string(),
            }),
        }))
        .await;

    match response {
        Ok(_) => panic!("machine deletion is not failed."),
        Err(x) => {
            let c = x.code();
            match c {
                Code::InvalidArgument => {
                    let msg = String::from(x.message());
                    if !msg.contains("Already a machine") {
                        panic!("machine interface deletion failed with wrong message {msg}");
                    }
                    return Ok(());
                }
                _ => {
                    panic!("machine interface deletion failed with wrong code {c}");
                }
            }
        }
    }
}

#[crate::sqlx_test]
async fn test_delete_bmc_interface_with_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host_config = env.managed_host_config();
    let _rpc_machine_id = create_dpu_machine(&env, &host_config).await;

    let mut txn = pool.begin().await?;
    let interfaces = db::machine_interface::find_all(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let interfaces = interfaces
        .iter()
        .filter(|x| x.attached_dpu_machine_id.is_none())
        .collect::<Vec<&MachineInterfaceSnapshot>>();
    if interfaces.len() != 2 {
        // We have only four interfaces, 2 for managed host and 2 for bmc (host and dpu).
        panic!("Wrong interface count {}.", interfaces.len());
    }

    let bmc_interface = interfaces[0];

    let response = env
        .api
        .delete_interface(tonic::Request::new(rpc::forge::InterfaceDeleteQuery {
            id: Some(rpc::Uuid {
                value: bmc_interface.id.to_string(),
            }),
        }))
        .await;

    match response {
        Ok(_) => panic!("machine deletion is not failed."),
        Err(x) => {
            let c = x.code();
            match c {
                Code::InvalidArgument => {
                    let msg = String::from(x.message());
                    if !msg.contains("This looks like a BMC interface and attached") {
                        panic!("machine interface deletion failed with wrong message {msg}");
                    }
                    return Ok(());
                }
                _ => {
                    panic!("machine interface deletion failed with wrong code {c}");
                }
            }
        }
    }
}

#[crate::sqlx_test]
async fn test_hostname_equals_ip(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let network_segment = NetworkSegment::admin(&mut txn).await?;
    let interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        Some(env.domain.into()),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .unwrap();

    assert_eq!(
        interface.hostname,
        interface
            .addresses
            .iter()
            .find(|x| x.is_ipv4())
            .unwrap()
            .to_string()
            .replace('.', "-")
    );
    Ok(())
}
