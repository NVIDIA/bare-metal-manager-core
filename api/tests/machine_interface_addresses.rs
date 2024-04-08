/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::str::FromStr;

use carbide::db::address_selection_strategy::AddressSelectionStrategy;
use carbide::db::machine_interface::MachineInterface;
use carbide::db::machine_interface_address::MachineInterfaceAddress;
use carbide::db::network_prefix::NewNetworkPrefix;
use carbide::db::network_segment::{NetworkSegmentType, NewNetworkSegment};
use carbide::model::network_segment::NetworkSegmentControllerState;
use ipnetwork::IpNetwork;
use std::net::IpAddr;

pub mod common;
use mac_address::MacAddress;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn find_by_address_bmc(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let new_ns = NewNetworkSegment {
        name: "PDX01-M01-H14-IPMITOR-01".to_string(),
        // domain id from tests/fixtures/create_domain.sql
        subdomain_id: Some(uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e")),
        vpc_id: None,
        mtu: 1490,
        prefixes: vec![NewNetworkPrefix {
            prefix: IpNetwork::V4("192.168.0.0/24".parse().unwrap()),
            gateway: Some(IpAddr::V4("192.168.0.1".parse().unwrap())),
            num_reserved: 14,
        }],
        vlan_id: None,
        vni: None,
        segment_type: NetworkSegmentType::Underlay,
        id: uuid::uuid!("f9860f19-37d5-44f6-b637-84de4648cd39"),
    };
    let network_segment = new_ns
        .persist(&mut txn, NetworkSegmentControllerState::Ready)
        .await?;
    // An interface that isn't attached to a Machine. This is what BMC interfaces are.
    let interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        &MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        Some(uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e")),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;
    let bmc_ip = interface
        .addresses()
        .iter()
        .find(|x| x.is_ipv4())
        .map(|x| x.address);
    assert!(bmc_ip.is_some());
    let res = MachineInterfaceAddress::find_by_address(&mut txn, bmc_ip.unwrap()).await?;
    assert!(res.is_some());
    assert_eq!(res.unwrap().interface_id, interface.id);

    Ok(())
}
