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
pub(crate) mod common;
mod connected_device;
mod create_domain;
mod desired_firmware_versions;
mod dns;
mod dpa_interfaces;
mod dpf;
mod dpu_agent_upgrade;
mod dpu_info_list;
mod dpu_machine_inventory;
mod dpu_machine_update;
mod dpu_nic_firmware;
mod dpu_remediation;
mod dpu_reprovisioning;
mod dynamic_config;
mod expected_machine;
mod expected_power_shelf;
mod explored_endpoint_find;
mod explored_managed_host_find;
mod extension_service;
mod finder;
mod host_bmc_firmware_test;
mod ib_fabric_find;
mod ib_fabric_monitor;
mod ib_instance;
mod ib_machine;
mod ib_partition_find;
mod ib_partition_lifecycle;
mod instance;
mod instance_allocate;
mod instance_batch_allocate;
mod instance_config_update;
mod instance_find;
mod instance_ipxe_behaviors;
mod instance_os;
mod instance_type;
mod ipxe;
mod level_filter;
mod lldp;
mod mac_address_pool;
mod machine_admin_force_delete;
mod machine_bmc_metadata;
mod machine_boot_override;
mod machine_creator;
mod machine_dhcp;
mod machine_discovery;
mod machine_find;
mod machine_health;
mod machine_history;
mod machine_interface_addresses;
mod machine_interfaces;
mod machine_metadata;
mod machine_network;
mod machine_power;
mod machine_states;
mod machine_topology;
pub mod machine_update_manager;
mod machine_validation;
mod maintenance;
#[cfg(feature = "linux-build")]
mod measured_boot;
mod mqtt_state_change_hook;
mod network_device;
mod network_security_group;
mod network_segment;
mod network_segment_find;
mod network_segment_lifecycle;
mod nvl_instance;
mod nvl_logical_partition;
mod power_shelf;
mod power_shelf_state_controller;
mod prevent_duplicate_mac_addresses;
mod rack_firmware;
mod rack_state_controller;
mod redfish_actions;
mod resource_pool;
mod route_servers;
mod service_health_metrics;
mod site_explorer;
mod sku;
mod spdm;
mod state_controller;
mod storage;
mod switch;
mod switch_state_controller;
mod tenant_keyset_find;
mod tenants;
mod test_meter;
mod tpm_ca;
mod vpc;
mod vpc_find;
mod vpc_peering;
mod vpc_prefix;
mod web;

pub use db::migrations::MIGRATOR;

/// Make these symols available as crate::tests::MIGRATOR and crate::tests::sqlx_fixture_from_str,
/// so that the [`carbide_macros::sqlx_test`] can delegate to them.
pub use crate::tests::common::sqlx_fixtures::sqlx_fixture_from_str;

/// Setup logging for tests.
#[ctor::ctor]
fn setup_test_logging() {
    use tracing::metadata::LevelFilter;
    use tracing_subscriber::filter::EnvFilter;
    use tracing_subscriber::fmt::TestWriter;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::util::SubscriberInitExt;

    if let Err(e) = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::Layer::default()
                .compact()
                .with_writer(TestWriter::new),
        )
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive("sqlx=warn".parse().unwrap())
                .add_directive("tower=warn".parse().unwrap())
                .add_directive("rustify=off".parse().unwrap())
                .add_directive("rustls=warn".parse().unwrap())
                .add_directive("hyper=warn".parse().unwrap())
                .add_directive("h2=warn".parse().unwrap())
                // Silence permissive mode related messages
                .add_directive("carbide::auth=error".parse().unwrap()),
        )
        .try_init()
    {
        // Note: Resist the temptation to ignore this error. We really should only have one place in
        // the test binary that initializes logging.
        panic!(
            "Failed to initialize trace logging for carbide-api tests. It's possible some earlier \
            code path has already set a global default log subscriber: {e}"
        );
    }
}
