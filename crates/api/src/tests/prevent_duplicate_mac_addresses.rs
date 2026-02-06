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
use db::{self, ObjectColumnFilter, network_segment};
use model::address_selection_strategy::AddressSelectionStrategy;
use model::machine::machine_id::from_hardware_info;

use crate::DatabaseError;
use crate::tests::common::api_fixtures::create_test_env;

#[crate::sqlx_test]
async fn prevent_duplicate_mac_addresses(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu = host_config.get_and_assert_single_dpu();

    let mut txn = env.pool.begin().await?;

    let network_segment = db::network_segment::find_by(
        &mut txn,
        ObjectColumnFilter::One(network_segment::IdColumn, &env.admin_segment.unwrap()),
        model::network_segment::NetworkSegmentSearchConfig::default(),
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
    db::machine::get_or_create(&mut txn, None, &machine_id, &new_interface).await?;

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
        Err(DatabaseError::NetworkSegmentDuplicateMacAddress(_))
    ));

    Ok(())
}
