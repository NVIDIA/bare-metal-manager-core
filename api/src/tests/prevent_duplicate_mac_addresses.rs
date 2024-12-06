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
use crate::db::{
    self, address_selection_strategy::AddressSelectionStrategy, machine::Machine, network_segment,
    network_segment::NetworkSegment, ObjectColumnFilter,
};
use crate::model::machine::machine_id::from_hardware_info;
use crate::CarbideError;

use crate::tests::common;
use common::api_fixtures::network_segment::FIXTURE_NETWORK_SEGMENT_ID;

use crate::tests::common::api_fixtures::create_test_env;

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn prevent_duplicate_mac_addresses(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu = host_sim.config.get_and_assert_single_dpu();

    let mut txn = env.pool.begin().await?;

    let network_segment = NetworkSegment::find_by(
        &mut txn,
        ObjectColumnFilter::One(network_segment::IdColumn, &FIXTURE_NETWORK_SEGMENT_ID),
        crate::db::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?
    .pop()
    .unwrap();

    let new_interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &dpu.oob_mac_address,
        None,
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let machine_id = from_hardware_info(&dpu.into()).unwrap();
    Machine::get_or_create(&mut txn, &machine_id, &new_interface).await?;

    let duplicate_interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &dpu.oob_mac_address,
        None,
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await;

    txn.commit().await?;

    assert!(matches!(
        duplicate_interface,
        Err(CarbideError::NetworkSegmentDuplicateMacAddress(_))
    ));

    Ok(())
}
