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

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use carbide_uuid::infiniband::IBPartitionId;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::MachineId;
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter, clock};
use nonzero_ext::nonzero;
use rpc::forge_tls_client::ForgeClientConfig;

const PHONE_HOME_RATE_LIMIT: Quota = Quota::per_minute(nonzero!(10u32));

/// Shared state between the gRPC server (writer) and REST server (reader).
pub struct FmdsState {
    pub config: ArcSwapOption<FmdsConfig>,
    pub machine_id: ArcSwapOption<MachineId>,
    pub forge_api: String,
    pub forge_client_config: Option<Arc<ForgeClientConfig>>,
    pub outbound_governor:
        Arc<RateLimiter<NotKeyed, InMemoryState, clock::DefaultClock, NoOpMiddleware>>,
}

impl FmdsState {
    pub fn new(forge_api: String, forge_client_config: Option<Arc<ForgeClientConfig>>) -> Self {
        Self {
            config: ArcSwapOption::new(None),
            machine_id: ArcSwapOption::new(None),
            forge_api,
            forge_client_config,
            outbound_governor: Arc::new(RateLimiter::direct(PHONE_HOME_RATE_LIMIT)),
        }
    }

    pub fn update_config(&self, config: FmdsConfig) {
        // Stash the machine_id separately for phone_home lookups.
        if let Some(ref mid) = config.machine_id {
            self.machine_id.store(Some(Arc::new(*mid)));
        }
        self.config.store(Some(Arc::new(config)));
    }
}

/// FmdsConfig is the data FMDS serves to tenants.
/// Populated from FmdsConfigUpdate proto.
#[derive(Clone, Debug)]
pub struct FmdsConfig {
    pub address: String,
    pub hostname: String,
    pub sitename: Option<String>,
    pub instance_id: Option<InstanceId>,
    pub machine_id: Option<MachineId>,
    pub user_data: String,
    pub ib_devices: Option<Vec<IBDeviceConfig>>,
    pub asn: u32,
}

#[derive(Clone, Debug)]
pub struct IBDeviceConfig {
    pub pf_guid: String,
    pub instances: Vec<IBInstanceConfig>,
}

#[derive(Clone, Debug)]
pub struct IBInstanceConfig {
    pub ib_partition_id: Option<IBPartitionId>,
    pub ib_guid: Option<String>,
    pub lid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_config() -> FmdsConfig {
        FmdsConfig {
            address: "10.0.0.1".to_string(),
            hostname: "test-host".to_string(),
            sitename: Some("test-site".to_string()),
            instance_id: Some(uuid::uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8").into()),
            machine_id: Some(
                "fm100ht6n80e7do39u8gmt7cvhm89pb32st9ngevgdolu542l1nfa4an0rg"
                    .parse()
                    .unwrap(),
            ),
            user_data: "cloud-init-data".to_string(),
            ib_devices: None,
            asn: 65000,
        }
    }

    #[test]
    fn test_new_state_starts_empty() {
        let state = FmdsState::new("https://api.test".to_string(), None);
        assert!(state.config.load_full().is_none());
        assert!(state.machine_id.load_full().is_none());
    }

    #[test]
    fn test_update_config_stores_config() {
        let state = FmdsState::new("https://api.test".to_string(), None);
        let config = make_test_config();

        state.update_config(config);

        let loaded = state.config.load_full().unwrap();
        assert_eq!(loaded.address, "10.0.0.1");
        assert_eq!(loaded.hostname, "test-host");
        assert_eq!(loaded.sitename.as_deref(), Some("test-site"));
        assert_eq!(loaded.user_data, "cloud-init-data");
        assert_eq!(loaded.asn, 65000);
    }

    #[test]
    fn test_update_config_extracts_machine_id() {
        let state = FmdsState::new("https://api.test".to_string(), None);
        let config = make_test_config();
        let expected_mid = config.machine_id.unwrap();

        state.update_config(config);

        let loaded_mid = state.machine_id.load_full().unwrap();
        assert_eq!(*loaded_mid, expected_mid);
    }

    #[test]
    fn test_update_config_without_machine_id() {
        let state = FmdsState::new("https://api.test".to_string(), None);
        let config = FmdsConfig {
            machine_id: None,
            ..make_test_config()
        };

        state.update_config(config);

        assert!(state.config.load_full().is_some());
        assert!(state.machine_id.load_full().is_none());
    }

    #[test]
    fn test_update_config_replaces_previous() {
        let state = FmdsState::new("https://api.test".to_string(), None);

        state.update_config(make_test_config());
        assert_eq!(state.config.load_full().unwrap().hostname, "test-host");

        state.update_config(FmdsConfig {
            hostname: "updated-host".to_string(),
            ..make_test_config()
        });
        assert_eq!(state.config.load_full().unwrap().hostname, "updated-host");
    }
}
