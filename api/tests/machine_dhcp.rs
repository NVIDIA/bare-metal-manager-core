/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use log::LevelFilter;

use mac_address::MacAddress;
use std::str::FromStr;

use carbide::db::machine_interface::MachineInterface;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_dhcp(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let test_mac_address = MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap();
    let test_gateway_address = "192.0.2.1".parse().unwrap();

    MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        test_mac_address,
        test_gateway_address,
    )
    .await?;

    txn.commit().await.unwrap();

    Ok(())
}
