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

use carbide_uuid::power_shelf::{PowerShelfId, PowerShelfIdSource, PowerShelfType};
use carbide_uuid::rack::{RackId, RackProfileId};
use carbide_uuid::switch::{SwitchId, SwitchIdSource, SwitchType};
use model::power_shelf::{NewPowerShelf, PowerShelfConfig, power_shelf_id};
use model::rack::RackConfig;
use model::switch::{NewSwitch, SwitchConfig, switch_id};

use crate::TestHarness;

pub struct TestRack {
    pub id: RackId,
}

impl TestRack {
    pub(crate) async fn create(test_harness: &TestHarness) -> Self {
        let id = RackId::new(uuid::Uuid::new_v4().to_string());
        let rack_profile_id = RackProfileId::new("rack");
        let mut txn = test_harness.db_txn().await;
        db::rack::create(
            &mut txn,
            &id,
            Some(&rack_profile_id),
            &RackConfig::default(),
            None,
        )
        .await
        .expect("rack should be created");
        txn.commit()
            .await
            .expect("database transaction should commit");
        Self { id }
    }
}

pub struct TestSwitch {
    pub id: SwitchId,
}

impl TestSwitch {
    pub(crate) async fn create(
        test_harness: &TestHarness,
        slot_number: i32,
        tray_index: i32,
    ) -> Self {
        let name = format!("Test Switch {}", &uuid::Uuid::new_v4().to_string()[..8]);
        let id = switch_id::from_hardware_info(
            &name,
            "NVIDIA",
            "Switch",
            SwitchIdSource::ProductBoardChassisSerial,
            SwitchType::NvLink,
        )
        .expect("switch id should be derived from test hardware info");
        let new_switch = NewSwitch {
            id,
            config: SwitchConfig {
                name,
                enable_nmxc: false,
                fabric_manager_config: None,
            },
            bmc_mac_address: None,
            metadata: None,
            rack_id: None,
            slot_number: Some(slot_number),
            tray_index: Some(tray_index),
        };

        let mut txn = test_harness.db_txn().await;
        db::switch::create(&mut txn, &new_switch)
            .await
            .expect("switch should be created");
        txn.commit()
            .await
            .expect("database transaction should commit");
        Self { id }
    }
}

pub struct TestPowerShelf {
    pub id: PowerShelfId,
}

impl TestPowerShelf {
    pub(crate) async fn create(test_harness: &TestHarness) -> Self {
        let name = format!(
            "Test Power Shelf {}",
            &uuid::Uuid::new_v4().to_string()[..8]
        );
        let id = power_shelf_id::from_hardware_info(
            &name,
            "NVIDIA",
            "PowerShelf",
            PowerShelfIdSource::ProductBoardChassisSerial,
            PowerShelfType::Rack,
        )
        .expect("power shelf id should be derived from test hardware info");
        let new_power_shelf = NewPowerShelf {
            id,
            config: PowerShelfConfig {
                name,
                capacity: Some(100),
                voltage: Some(240),
            },
            bmc_mac_address: None,
            metadata: None,
            rack_id: None,
        };

        let mut txn = test_harness.db_txn().await;
        db::power_shelf::create(&mut txn, &new_power_shelf)
            .await
            .expect("power shelf should be created");
        txn.commit()
            .await
            .expect("database transaction should commit");
        Self { id }
    }
}
