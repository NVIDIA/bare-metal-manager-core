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

#[cfg(test)]
mod client_resolution;
pub mod common;
#[cfg(test)]
mod compute_allocation;
#[cfg(test)]
mod connected_device;
#[cfg(test)]
mod create_domain;
#[cfg(test)]
mod credential;
#[cfg(test)]
mod dhcp_lease_expiration;
#[cfg(test)]
mod dns;
#[cfg(test)]
mod dpa_interfaces;
#[cfg(test)]
mod dpf;
#[cfg(test)]
mod dpu_agent_upgrade;
#[cfg(test)]
mod dpu_info_list;
#[cfg(test)]
mod dpu_machine_inventory;
#[cfg(test)]
mod dpu_machine_update;
#[cfg(test)]
mod dpu_nic_firmware;
#[cfg(test)]
mod dpu_remediation;
#[cfg(test)]
mod dpu_reprovisioning;
#[cfg(test)]
mod dynamic_config;
#[cfg(test)]
mod expected_machine;
#[cfg(test)]
mod expected_power_shelf;
#[cfg(test)]
mod expected_rack;
#[cfg(test)]
mod expected_switch;
#[cfg(test)]
mod explored_endpoint_find;
#[cfg(test)]
mod explored_managed_host_find;
#[cfg(test)]
mod extension_service;
#[cfg(test)]
mod finder;
#[cfg(test)]
mod host_bmc_firmware_test;
#[cfg(test)]
mod ib_fabric_find;
#[cfg(test)]
mod ib_fabric_monitor;
#[cfg(test)]
mod ib_instance;
#[cfg(test)]
mod ib_machine;
#[cfg(test)]
mod ib_partition_find;
#[cfg(test)]
mod ib_partition_lifecycle;
#[cfg(test)]
mod instance;
#[cfg(test)]
mod instance_allocate;
#[cfg(test)]
mod instance_batch_allocate;
#[cfg(test)]
mod instance_config_update;
#[cfg(test)]
mod instance_find;
#[cfg(test)]
mod instance_ipxe_behaviors;
#[cfg(test)]
mod instance_os;
#[cfg(test)]
mod instance_type;
#[cfg(test)]
mod ip_allocator;
#[cfg(test)]
mod ipxe;
#[cfg(test)]
mod level_filter;
#[cfg(test)]
mod lldp;
#[cfg(test)]
mod mac_address_pool;
#[cfg(test)]
mod machine_admin_force_delete;
#[cfg(test)]
mod machine_bmc_metadata;
#[cfg(test)]
mod machine_boot_override;
#[cfg(test)]
mod machine_creator;
#[cfg(test)]
mod machine_dhcp;
#[cfg(test)]
mod machine_discovery;
#[cfg(test)]
mod machine_find;
#[cfg(test)]
mod machine_health;
#[cfg(test)]
mod machine_history;
#[cfg(test)]
mod machine_interface_addresses;
#[cfg(test)]
mod machine_interfaces;
#[cfg(test)]
mod machine_metadata;
#[cfg(test)]
mod machine_network;
#[cfg(test)]
mod machine_power;
#[cfg(test)]
mod machine_setup;
#[cfg(test)]
mod machine_states;
#[cfg(test)]
mod machine_topology;
#[cfg(test)]
pub mod machine_update_manager;
#[cfg(test)]
mod machine_validation;
#[cfg(test)]
mod maintenance;
#[cfg(feature = "linux-build")]
#[cfg(test)]
mod measured_boot;
#[cfg(test)]
mod mqtt_state_change_hook;
#[cfg(test)]
mod network_device;
#[cfg(test)]
mod network_security_group;
#[cfg(test)]
mod network_segment;
#[cfg(test)]
mod network_segment_find;
#[cfg(test)]
mod network_segment_lifecycle;
#[cfg(test)]
mod nvl_instance;
#[cfg(test)]
mod nvl_logical_partition;
#[cfg(test)]
mod nvlink_domain_health;
#[cfg(test)]
mod operating_system;
#[cfg(test)]
mod power_shelf;
#[cfg(test)]
mod power_shelf_find;
#[cfg(test)]
mod power_shelf_health;
#[cfg(test)]
mod power_shelf_metadata;
#[cfg(test)]
mod power_shelf_state_controller;
#[cfg(test)]
mod preingestion_dpu_nic_mode;
#[cfg(test)]
mod prevent_duplicate_mac_addresses;
#[cfg(test)]
mod rack_find;
#[cfg(test)]
mod rack_health;
#[cfg(test)]
mod rack_metadata;
#[cfg(test)]
mod rack_state_controller;
#[cfg(test)]
mod redfish_actions;
#[cfg(test)]
mod resource_pool;
#[cfg(test)]
mod route_servers;
#[cfg(test)]
mod service_health_metrics;
#[cfg(test)]
mod set_primary_dpu;
#[cfg(test)]
mod site_explorer;
#[cfg(test)]
mod sku;
#[cfg(test)]
mod spdm;
#[cfg(test)]
mod static_address_management;
#[cfg(test)]
mod storage;
#[cfg(test)]
mod switch;
#[cfg(test)]
mod switch_find;
#[cfg(test)]
mod switch_health;
#[cfg(test)]
mod switch_metadata;
#[cfg(test)]
mod switch_state_controller;
#[cfg(test)]
mod tenant_keyset_find;
#[cfg(test)]
mod tenants;
#[cfg(test)]
mod tpm_ca;
#[cfg(test)]
mod vpc;
#[cfg(test)]
mod vpc_find;
#[cfg(test)]
mod vpc_peering;
#[cfg(test)]
mod vpc_prefix;
// NOTE: the admin web UI tests moved to the `carbide-api-web` crate (alongside the web code they
// exercise). They build an `Api` via the `tests::common` fixtures, which `carbide-api-web` reaches
// through this crate's `test-support` feature.

/// Make these symbol available as
/// crate::tests::sqlx_fixture_from_str, so that the
/// [`carbide_macros::sqlx_test`] can delegate to them.
pub use crate::tests::common::sqlx_fixtures::sqlx_fixture_from_str;

/// Setup logging for tests. Only our own test binary needs this global initializer (it depends on
/// the dev-only `ctor` crate); consumers of the `test-support` fixtures bring their own logging.
#[cfg(test)]
#[ctor::ctor(unsafe)]
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
                .add_directive("carbide_api_core::auth=error".parse().unwrap()),
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
