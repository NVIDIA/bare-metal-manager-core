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
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use mac_address::MacAddress;
use model::address_selection_strategy::AddressSelectionStrategy;

use crate::tests::common::api_fixtures::create_test_env;

#[crate::sqlx_test]
async fn test_next_machine_interface_v4_ip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let network_segment = db::network_segment::admin(&mut txn).await?;
    let network_prefix = network_segment
        .prefixes
        .first()
        .expect("network_segment should have had at least one prefix");

    // The next IP should be .3, since num_reserved = 3.
    let expected_ip = match network_prefix.prefix.ip() {
        IpAddr::V4(ip) => {
            let [o1, o2, o3, _] = ip.octets();
            Ipv4Addr::new(
                o1,
                o2,
                o3,
                network_prefix
                    .num_reserved
                    .try_into()
                    .expect("too many reserved IPs in admin segment"),
            )
        }
        _ => panic!("only v4 prefixes are currently supported"),
    };

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
        interface.addresses.len(),
        1,
        "interface should have had 1 address allocated"
    );
    assert_eq!(
        interface.addresses[0], expected_ip,
        "interface address should match the next IP from before creation"
    );

    let next_ip = db::ip_allocator::next_machine_interface_v4_ip(&mut txn, network_prefix)
        .await?
        .expect("Network prefix should have an IP available");

    assert_ne!(
        next_ip, expected_ip,
        "we should get a different next IP after creation"
    );

    Ok(())
}
