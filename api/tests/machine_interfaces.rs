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

use std::{collections::HashSet, str::FromStr};

use carbide::{
    db::{
        address_selection_strategy::AddressSelectionStrategy, dhcp_entry::DhcpEntry,
        domain::Domain, machine::Machine, machine_interface::MachineInterface,
        network_segment::NetworkSegment, UuidKeyedObjectFilter,
    },
    model::machine::machine_id::{try_parse_machine_id, MachineId},
    CarbideError,
};
use itertools::Itertools;
use mac_address::MacAddress;
use rpc::forge::{forge_server::Forge, InterfaceSearchQuery};
use sqlx::{Connection, Postgres};

pub mod common;
use common::api_fixtures::{
    create_test_env, dpu::create_dpu_hardware_info, network_segment::FIXTURE_NETWORK_SEGMENT_ID,
    FIXTURE_DHCP_RELAY_ADDRESS,
};
use tokio::sync::broadcast;
use tonic::Code;

use crate::common::api_fixtures::dpu::create_dpu_machine;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

async fn get_fixture_network_segment(
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<NetworkSegment, Box<dyn std::error::Error>> {
    carbide::db::network_segment::NetworkSegment::find(
        txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_NETWORK_SEGMENT_ID),
        carbide::db::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?
    .pop()
    .ok_or_else(|| {
        format!(
            "Can't find the Network Segment by well-known-uuid: {}",
            FIXTURE_NETWORK_SEGMENT_ID
        )
        .into()
    })
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn only_one_primary_interface_per_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let other_host_sim = env.start_managed_host_sim();

    let mut txn = env.pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;

    let new_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        &host_sim.config.dpu_oob_mac_address,
        None,
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let machine_id =
        MachineId::from_hardware_info(&create_dpu_hardware_info(&host_sim.config)).unwrap();
    let (new_machine, _is_new) = Machine::get_or_create(&mut txn, &machine_id, &new_interface)
        .await
        .expect("Unable to create machine");

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await?;

    let should_failed_machine_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        &other_host_sim.config.dpu_oob_mac_address,
        None,
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let output = should_failed_machine_interface
        .associate_interface_with_machine(&mut txn, new_machine.id())
        .await;

    txn.commit().await.unwrap();

    assert!(matches!(output, Err(CarbideError::OnePrimaryInterface)));

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn many_non_primary_interfaces_per_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;

    MachineInterface::create(
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
    let mut txn = pool.begin().await?;

    let should_be_ok_interface = MachineInterface::create(
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn return_existing_machine_interface_on_rediscover(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: This tests only DHCP without Machines. For Interfaces with a Machine,
    // there are tests in `machine_dhcp.rs`
    // This should also be migrated to use actual API calls
    let mut txn = pool.begin().await?;

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_machine = MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        test_mac,
        FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap(),
    )
    .await?;

    let existing_machine = MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        test_mac,
        FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap(),
    )
    .await?;

    assert_eq!(new_machine.id(), existing_machine.id());

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn find_all_interfaces_test_cases(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut txn = env.pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;
    let domain_ids = Domain::find(&mut txn, UuidKeyedObjectFilter::All).await?;
    let domain_id = domain_ids[0].id;
    let mut interfaces: Vec<MachineInterface> = Vec::new();
    for i in 0..2 {
        let interface = MachineInterface::create(
            &mut txn,
            &network_segment,
            MacAddress::from_str(format!("ff:ff:ff:ff:ff:0{}", i).as_str())
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
    }

    txn.commit().await?;
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
    for (idx, interface) in interfaces.iter().enumerate().take(2) {
        assert_eq!(response.interfaces[idx].hostname, interface.hostname());
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn find_interfaces_test_cases(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();

    let mut txn = env.pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;
    let domain_ids = Domain::find(&mut txn, UuidKeyedObjectFilter::All).await?;
    let domain_id = domain_ids[0].id;
    let new_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        &host_sim.config.dpu_oob_mac_address,
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
    assert_eq!(response.interfaces[0].hostname, new_interface.hostname());
    assert_eq!(
        response.interfaces[0].mac_address,
        new_interface.mac_address.to_string()
    );
    assert_eq!(
        response.interfaces[0].vendor.clone().unwrap().to_string(),
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn create_parallel_mi(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let network = NetworkSegment::find(
        &mut txn,
        UuidKeyedObjectFilter::One(
            uuid::Uuid::from_str("91609f10-c91d-470d-a260-6293ea0c1200").unwrap(),
        ),
        carbide::db::network_segment::NetworkSegmentSearchConfig {
            include_history: false,
            include_num_free_ips: false,
        },
    )
    .await
    .unwrap()
    .remove(0);
    txn.commit().await.unwrap();

    let (tx, _rx1) = broadcast::channel(10);
    let max_interfaces = 250;
    let mut handles = vec![];
    for i in 0..max_interfaces {
        let n = network.clone();
        let mac = format!("ff:ff:ff:ff:{:02}:{:02}", i / 100, i % 100);
        let db_pool = pool.clone();
        let mut rx = tx.subscribe();
        let h = tokio::spawn(async move {
            // Let's start all threads together.
            _ = rx.recv().await.unwrap();
            let mut txn = db_pool.begin().await.unwrap();
            MachineInterface::create(
                &mut txn,
                &n,
                &MacAddress::from_str(&mac).unwrap(),
                Some(uuid::Uuid::from_str("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e").unwrap()),
                true,
                AddressSelectionStrategy::Automatic,
            )
            .await
            .unwrap();

            // This call must pass. inner_txn is an illusion. Lock is still alive.
            _ = MachineInterface::find_all(&mut txn).await.unwrap();
            txn.commit().await.unwrap();
        });
        handles.push(h);
    }

    tx.send(10).unwrap();

    for h in handles {
        _ = h.await;
    }
    let mut txn = pool.begin().await?;
    let interfaces = MachineInterface::find_all(&mut txn).await.unwrap();

    assert_eq!(interfaces.len(), max_interfaces);
    let ips = interfaces
        .iter()
        .map(|x| x.addresses()[0].address.to_string())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect_vec();
    assert_eq!(interfaces.len(), ips.len());

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_by_ip_or_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;
    let interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        Some(uuid::Uuid::from_str("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e").unwrap()),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .unwrap();

    // By remote IP
    let remote_ip = Some(interface.addresses()[0].address);
    let interface_id = None;
    let iface = MachineInterface::find_by_ip_or_id(&mut txn, remote_ip, interface_id).await?;
    assert_eq!(iface.id, interface.id);

    // By interface ID
    let remote_ip = None;
    let interface_id = Some(iface.id);
    let iface = MachineInterface::find_by_ip_or_id(&mut txn, remote_ip, interface_id).await?;
    assert_eq!(iface.id, interface.id);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_delete_interface(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;
    let interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        Some(uuid::Uuid::from_str("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e").unwrap()),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .unwrap();

    txn.commit().await.unwrap();

    let mut txn = pool.begin().await?;
    interface.delete(&mut txn).await?;
    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let _interface = MachineInterface::find_one(&mut txn, interface.id).await;
    assert!(matches!(
        CarbideError::FindOneReturnedNoResultsError(interface.id),
        _interface
    ));

    txn.commit().await?;

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_delete_interface_with_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let rpc_machine_id = create_dpu_machine(&env, &host_sim.config).await;
    let dpu_machine_id = try_parse_machine_id(&rpc_machine_id).unwrap();

    let mut txn = pool.begin().await?;
    let interface = MachineInterface::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()])
        .await
        .unwrap();

    let interface = &interface.get(&dpu_machine_id).unwrap()[0];
    txn.commit().await.unwrap();

    let response = env
        .api
        .delete_interface(tonic::Request::new(rpc::forge::InterfaceDeleteQuery {
            id: Some(rpc::Uuid {
                value: interface.id().to_string(),
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_delete_bmc_interface_with_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let _rpc_machine_id = create_dpu_machine(&env, &host_sim.config).await;

    let mut txn = pool.begin().await?;
    let interfaces = MachineInterface::find_all(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let interfaces = interfaces
        .iter()
        .filter(|x| x.attached_dpu_machine_id().is_none())
        .collect::<Vec<&MachineInterface>>();

    if interfaces.len() != 1 {
        // We have only three interfaces, 2 for managed host and one for bmc.
        panic!("Wrong interface count {}.", interfaces.len());
    }

    let bmc_interface = interfaces[0];

    let response = env
        .api
        .delete_interface(tonic::Request::new(rpc::forge::InterfaceDeleteQuery {
            id: Some(rpc::Uuid {
                value: bmc_interface.id().to_string(),
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_hostname_equals_ip(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;
    let interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        Some(uuid::Uuid::from_str("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e").unwrap()),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .unwrap();

    assert_eq!(
        interface.hostname(),
        interface
            .addresses()
            .iter()
            .map(|x| x.address)
            .find(|x| x.is_ipv4())
            .unwrap()
            .to_string()
            .replace('.', "-")
    );
    Ok(())
}
