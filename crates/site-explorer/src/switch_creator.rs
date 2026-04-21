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

use carbide_uuid::switch::SwitchId;
use db::DatabaseError;
use model::expected_switch::ExpectedSwitch;
use model::site_explorer::ExploredManagedSwitch;
use sqlx::{PgConnection, PgPool};

use crate::SiteExplorerConfig;
use crate::errors::SiteExplorerResult;
use crate::explored_endpoint_index::ExploredEndpointIndex;
use crate::metrics::SiteExplorationMetrics;

pub struct SwitchCreator {
    database_connection: PgPool,
    config: SiteExplorerConfig,
}

impl SwitchCreator {
    pub fn new(database_connection: PgPool, config: SiteExplorerConfig) -> Self {
        Self {
            database_connection,
            config,
        }
    }

    pub(crate) async fn create_switches(
        &self,
        metrics: &mut SiteExplorationMetrics,
        explored_managed_switches: &[ExploredManagedSwitch],
        expected_explored_endpoint_index: &ExploredEndpointIndex,
    ) -> SiteExplorerResult<()> {
        for explored_managed_switch in explored_managed_switches {
            let expected_switch = match expected_explored_endpoint_index
                .matched_expected_switch(&explored_managed_switch.bmc_ip)
            {
                Some(expected_switch) => expected_switch,
                None => continue,
            };

            match self
                .create_managed_switch(
                    explored_managed_switch,
                    expected_switch,
                    &self.database_connection,
                )
                .await
            {
                Ok(true) => {
                    metrics.created_switches_count += 1;
                    if metrics.created_switches_count as u64 == self.config.switches_created_per_run
                    {
                        break;
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(
                        %error,
                        "Failed to create managed switch {:#?}",
                        explored_managed_switch.bmc_ip
                    );
                }
            }
        }

        Ok(())
    }

    pub async fn create_managed_switch(
        &self,
        explored_managed_switch: &ExploredManagedSwitch,
        expected_switch: &ExpectedSwitch,
        pool: &PgPool,
    ) -> SiteExplorerResult<bool> {
        let mut txn = pool
            .begin()
            .await
            .map_err(|e| DatabaseError::new("begin create_managed_switch", e))?;

        let created = self
            .create_switch(&mut txn, explored_managed_switch, expected_switch)
            .await?
            .is_some();

        txn.commit()
            .await
            .map_err(|e| DatabaseError::new("commit create_managed_switch", e))?;

        Ok(created)
    }

    async fn create_switch(
        &self,
        txn: &mut PgConnection,
        explored_managed_switch: &ExploredManagedSwitch,
        expected_switch: &ExpectedSwitch,
    ) -> SiteExplorerResult<Option<SwitchId>> {
        if !explored_managed_switch.nv_os_mac_addresses.is_empty() {
            let explored_macs = explored_managed_switch.nv_os_mac_addresses.clone();
            if *explored_macs != expected_switch.nvos_mac_addresses {
                db::expected_switch::update_nvos_mac_addresses(
                    &mut *txn,
                    expected_switch.bmc_mac_address,
                    &explored_macs,
                )
                .await?;
            }
        }
        let switch_id = explored_managed_switch
            .clone()
            .report
            .generate_switch_id()?
            .unwrap();

        tracing::info!(%switch_id, "switch ID generated");

        let existing_switch = db::switch::find_by_id(txn, &switch_id).await?;

        if let Some(_existing_switch) = existing_switch {
            tracing::warn!(
                %switch_id,
                "Switch already exists, skipping. {} for switch id",
                switch_id.to_string()
            );
            return Ok(None);
        }
        self.create_switch_from_explored_switch(txn, expected_switch, switch_id)
            .await?;
        Ok(Some(switch_id))
    }

    async fn create_switch_from_explored_switch(
        &self,
        txn: &mut PgConnection,
        expected_switch: &ExpectedSwitch,
        switch_id: SwitchId,
    ) -> SiteExplorerResult<()> {
        let name = match expected_switch.metadata.name.is_empty() {
            true => expected_switch.serial_number.to_string(),
            false => expected_switch.metadata.name.to_string(),
        };

        let config = model::switch::SwitchConfig {
            name,
            enable_nmxc: false,
            fabric_manager_config: None,
        };

        let new_switch = model::switch::NewSwitch {
            id: switch_id,
            slot_number: None,
            tray_index: None,
            config,
            bmc_mac_address: Some(expected_switch.bmc_mac_address),
            metadata: Some(expected_switch.metadata.clone()),
            rack_id: expected_switch.rack_id.clone(),
        };

        _ = db::switch::create(txn, &new_switch).await?;

        if let Some(ref rack_id) = expected_switch.rack_id {
            let _ = crate::ensure_rack_exists(&mut *txn, rack_id).await?;
        }

        Ok(())
    }
}
