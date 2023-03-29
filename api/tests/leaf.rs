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
use std::net::IpAddr;
use std::str::FromStr;

use log::LevelFilter;

use carbide::db::vpc_resource_leaf::{NewVpcResourceLeaf, VpcResourceLeaf};

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

const DPU_MACHINE_ID: &str = "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g";

#[sqlx::test]
async fn new_leafs_are_in_new_state(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let leaf = NewVpcResourceLeaf::new(DPU_MACHINE_ID.parse().unwrap())
        .persist(&mut txn)
        .await?;

    txn.commit().await?;
    let mut txn = pool.begin().await?;

    assert!(VpcResourceLeaf::find(&mut txn, leaf.id()).await.is_ok());

    Ok(())
}

#[sqlx::test]
async fn find_leaf_by_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let leaf = NewVpcResourceLeaf::new(DPU_MACHINE_ID.parse().unwrap())
        .persist(&mut txn)
        .await?;

    txn.commit().await?;
    let mut txn = pool.begin().await?;

    let leaf = VpcResourceLeaf::find(&mut txn, leaf.id()).await?;
    assert_eq!(leaf.id(), &DPU_MACHINE_ID.parse().unwrap());

    Ok(())
}

#[sqlx::test]
async fn find_leaf_and_update_loopback_ip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let leaf = NewVpcResourceLeaf::new(DPU_MACHINE_ID.parse().unwrap())
        .persist(&mut txn)
        .await?;
    assert!(leaf.loopback_ip_address().is_none());

    txn.commit().await?;

    let mut txn = pool.begin().await?;

    let address = IpAddr::from_str("1.2.3.4")?;

    let mut new_leaf = VpcResourceLeaf::find(&mut txn, leaf.id()).await?;

    new_leaf
        .update_loopback_ip_address(&mut txn, address)
        .await?;

    assert_eq!(
        new_leaf.loopback_ip_address().map(|ip| ip.to_string()),
        Some("1.2.3.4".to_string())
    );

    Ok(())
}
