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

use std::borrow::Borrow;
use std::collections::HashSet;
use std::str::FromStr;

use common::api_fixtures::{FIXTURE_DHCP_RELAY_ADDRESS, create_test_env};
use db::dhcp_entry::DhcpEntry;
use db::{self, ObjectColumnFilter};
use itertools::Itertools;
use mac_address::MacAddress;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::machine::MachineInterfaceSnapshot;
use model::machine::machine_id::from_hardware_info;
use model::machine_interface_address::MachineInterfaceAssociation;
use rpc::forge::InterfaceSearchQuery;
use rpc::forge::forge_server::Forge;
use tokio::sync::broadcast;
use tonic::Code;

use crate::DatabaseError;
use crate::tests::common;
use crate::tests::common::api_fixtures::dpu::create_dpu_machine;

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

    let network_segment = db::network_segment::admin(&mut txn).await?;

    let new_interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &dpu.oob_mac_address,
        None,
        true,
        AddressSelectionStrategy::NextAvailableIp,
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
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;

    let output = db::machine_interface::associate_interface_with_machine(
        &should_failed_machine_interface.id,
        MachineInterfaceAssociation::Machine(new_machine.id),
        &mut txn,
    )
    .await;

    txn.commit().await.unwrap();

    assert!(matches!(output, Err(DatabaseError::OnePrimaryInterface)));

    Ok(())
}

#[crate::sqlx_test]
async fn many_non_primary_interfaces_per_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;
    let network_segment = db::network_segment::admin(&mut txn).await?;

    db::machine_interface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        true,
        AddressSelectionStrategy::NextAvailableIp,
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
        AddressSelectionStrategy::NextAvailableIp,
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
        None,
    )
    .await?;

    let existing_machine = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        test_mac,
        FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap(),
        None,
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

    let network_segment = db::network_segment::admin(&mut txn).await?;
    let domain_ids = db::dns::domain::find_by(
        &mut txn,
        ObjectColumnFilter::<db::dns::domain::IdColumn>::All,
    )
    .await?;
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
            AddressSelectionStrategy::NextAvailableIp,
        )
        .await?;
        db::dhcp_entry::persist(
            DhcpEntry {
                machine_interface_id: interface.id,
                vendor_string: format!("NVIDIA {i} 1"),
            },
            &mut txn,
        )
        .await?;
        db::dhcp_entry::persist(
            DhcpEntry {
                machine_interface_id: interface.id,
                vendor_string: format!("NVIDIA {i} 2"),
            },
            &mut txn,
        )
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

    let network_segment = db::network_segment::admin(&mut txn).await?;
    let domain_ids = db::dns::domain::find_by(
        &mut txn,
        ObjectColumnFilter::<db::dns::domain::IdColumn>::All,
    )
    .await?;
    let domain_id = domain_ids[0].id;
    let new_interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &dpu.oob_mac_address,
        Some(domain_id),
        true,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;

    db::dhcp_entry::persist(
        DhcpEntry {
            machine_interface_id: new_interface.id,
            vendor_string: "NVIDIA".to_string(),
        },
        &mut txn,
    )
    .await?;
    db::dhcp_entry::persist(
        DhcpEntry {
            machine_interface_id: new_interface.id,
            vendor_string: "NVIDIA New".to_string(),
        },
        &mut txn,
    )
    .await?;
    txn.commit().await?;

    let response = env
        .api
        .find_interfaces(tonic::Request::new(InterfaceSearchQuery {
            id: Some(new_interface.id),
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
    let network = db::network_segment::admin(&mut txn).await?;
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
                AddressSelectionStrategy::NextAvailableIp,
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

    let network_segment = db::network_segment::admin(&mut txn).await?;
    let interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        Some(env.domain.into()),
        true,
        AddressSelectionStrategy::NextAvailableIp,
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
            desired_address: None,
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
    let interface_id = interface.id.unwrap();

    env.api
        .delete_interface(tonic::Request::new(rpc::forge::InterfaceDeleteQuery {
            id: Some(interface_id),
        }))
        .await
        .unwrap();

    let mut txn = env.pool.begin().await?;
    let _interface = db::machine_interface::find_one(&mut txn, interface_id).await;
    assert!(matches!(
        DatabaseError::FindOneReturnedNoResultsError(interface_id.into()),
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
            desired_address: None,
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
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;

    let mut txn = pool.begin().await?;
    let interface = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id])
        .await
        .unwrap();

    let interface = &interface.get(&dpu_machine_id).unwrap()[0];
    txn.commit().await.unwrap();

    let response = env
        .api
        .delete_interface(tonic::Request::new(rpc::forge::InterfaceDeleteQuery {
            id: Some(interface.id),
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
            id: Some(bmc_interface.id),
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

    let network_segment = db::network_segment::admin(&mut txn).await?;
    let interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        Some(env.domain.into()),
        true,
        AddressSelectionStrategy::NextAvailableIp,
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

#[crate::sqlx_test]
async fn test_max_one_interface_association(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    use carbide_uuid::power_shelf::PowerShelfId;
    use carbide_uuid::switch::SwitchId;
    use model::power_shelf::{NewPowerShelf, PowerShelfConfig};
    use model::switch::{NewSwitch, SwitchConfig};

    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let network_segment = db::network_segment::admin(&mut txn).await?;
    let interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        Some(env.domain.into()),
        true,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;

    // Create a switch and associate the interface with it
    let switch_id = SwitchId::from(uuid::Uuid::new_v4());
    let new_switch = NewSwitch {
        id: switch_id,
        config: SwitchConfig {
            name: "Test Switch".to_string(),
            enable_nmxc: false,
            fabric_manager_config: None,
            location: None,
        },
    };
    db::switch::create(&mut txn, &new_switch).await?;

    db::machine_interface::associate_interface_with_machine(
        &interface.id,
        MachineInterfaceAssociation::Switch(switch_id),
        &mut txn,
    )
    .await?;

    // Now try to associate the same interface with a power shelf - should fail
    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: PowerShelfConfig {
            name: "Test Power Shelf".to_string(),
            capacity: None,
            voltage: None,
            location: None,
        },
    };
    db::power_shelf::create(&mut txn, &new_power_shelf).await?;

    let output = db::machine_interface::associate_interface_with_machine(
        &interface.id,
        MachineInterfaceAssociation::PowerShelf(power_shelf_id),
        &mut txn,
    )
    .await;

    txn.commit().await.unwrap();

    assert!(matches!(
        output,
        Err(DatabaseError::MaxOneInterfaceAssociation)
    ));

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_association(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    use carbide_uuid::power_shelf::PowerShelfId;
    use model::power_shelf::{NewPowerShelf, PowerShelfConfig};

    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let network_segment = db::network_segment::admin(&mut txn).await?;
    let interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        Some(env.domain.into()),
        true,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;

    // Create a power shelf
    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: PowerShelfConfig {
            name: "Test Power Shelf".to_string(),
            capacity: Some(10000),
            voltage: Some(480),
            location: Some("Rack A1".to_string()),
        },
    };
    db::power_shelf::create(&mut txn, &new_power_shelf).await?;

    // Associate the interface with the power shelf
    let result = db::machine_interface::associate_interface_with_machine(
        &interface.id,
        MachineInterfaceAssociation::PowerShelf(power_shelf_id),
        &mut txn,
    )
    .await;

    txn.commit().await.unwrap();

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), interface.id);

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_association(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    use carbide_uuid::switch::SwitchId;
    use model::switch::{NewSwitch, SwitchConfig};

    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let network_segment = db::network_segment::admin(&mut txn).await?;
    let interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        Some(env.domain.into()),
        true,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;

    // Create a switch
    let switch_id = SwitchId::from(uuid::Uuid::new_v4());
    let new_switch = NewSwitch {
        id: switch_id,
        config: SwitchConfig {
            name: "Test Switch".to_string(),
            enable_nmxc: false,
            fabric_manager_config: None,
            location: Some("Rack B2".to_string()),
        },
    };
    db::switch::create(&mut txn, &new_switch).await?;

    // Associate the interface with the switch
    let result = db::machine_interface::associate_interface_with_machine(
        &interface.id,
        MachineInterfaceAssociation::Switch(switch_id),
        &mut txn,
    )
    .await;

    txn.commit().await.unwrap();

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), interface.id);

    Ok(())
}
