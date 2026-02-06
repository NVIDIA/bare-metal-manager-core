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
use std::net::SocketAddr;
use std::path::PathBuf;

use forge_secrets::forge_vault::VaultConfig;
use tokio::sync::oneshot::{Receiver, Sender};
use utils::HostPortPair;

use crate::utils::LOCALHOST_CERTS;

const DOMAIN_NAME: &str = "forge.integrationtest";

// Use a struct for the args to start() so that callers can see argument names
pub struct StartArgs {
    pub addr: SocketAddr,
    pub metrics_addr: SocketAddr,
    pub root_dir: PathBuf,
    pub db_url: String,
    pub bmc_proxy: Option<HostPortPair>,
    pub firmware_directory: PathBuf,
    pub stop_channel: Receiver<()>,
    pub ready_channel: Sender<()>,
    pub vault_config: VaultConfig,
}

pub async fn start(
    StartArgs {
        // Destructure start args
        addr,
        metrics_addr,
        root_dir,
        db_url,
        bmc_proxy,
        firmware_directory,
        stop_channel,
        ready_channel,
        vault_config,
    }: StartArgs,
) -> eyre::Result<()> {
    let firmware_directory_str = firmware_directory.to_string_lossy();
    let root_dir_str = root_dir.to_string_lossy();

    let root_cafile_path = LOCALHOST_CERTS.ca_cert.to_str().unwrap();
    let identity_pemfile_path = LOCALHOST_CERTS.server_cert.to_string_lossy();
    let identity_keyfile_path = LOCALHOST_CERTS.server_key.to_string_lossy();

    let carbide_config_str = {
        let bmc_proxy_cfg = if let Some(bmc_proxy) = bmc_proxy {
            format!(r#"bmc_proxy = "{bmc_proxy}""#)
        } else {
            // None is encoded by omitting the option altogether... just drop a comment
            String::from("# no bmc_proxy set")
        };

        let addr = format!("[::]:{}", addr.port());

        format!(
            r#"
        listen = "{addr}"
        metrics_endpoint = "{metrics_addr}"
        alt_metric_prefix = "alt_metric_"
        database_url = "{db_url}"
        max_database_connections = 1000
        asn = 65535
        dhcp_servers = []
        route_servers = []
        enable_route_servers = false
        deny_prefixes = []
        site_fabric_prefixes = []
        dpu_ipmi_tool_impl = "test"
        initial_domain_name = "{DOMAIN_NAME}"
        initial_dpu_agent_upgrade_policy = "off"
        max_concurrent_machine_updates = 1
        nvue_enabled = true
        attestation_enabled = false
        max_find_by_ids = 100
        internet_l3_vni = 1337
        bypass_rbac = true

        [ib_config]
        max_partition_per_tenant = 31
        enabled = false
        mtu = 4
        rate_limit = 200
        service_level = 0

        [tls]
        root_cafile_path = "{root_cafile_path}"
        identity_pemfile_path = "{identity_pemfile_path}"
        identity_keyfile_path = "{identity_keyfile_path}"
        admin_root_cafile_path = "nothing_will_read_from_this_during_integration_tests"

        [auth]
        permissive_mode = true
        casbin_policy_file = "{root_dir_str}/crates/api/casbin-policy.csv"

        [auth.trust]
        spiffe_trust_domain="nothing_will_read_from_this_during_integration_tests"
        spiffe_service_base_paths=["/nothing_will_read_from_this_during_integration_tests"]
        spiffe_machine_base_path="nothing_will_read_from_this_during_integration_tests"
        additional_issuer_cns=["nothing_will_read_from_this_during_integration_tests"]

        [pools.vpc-vni]
        type = "integer"

        [[pools.vpc-vni.ranges]]
        start = "2024500"
        end = "2024550"

        [pools.vlan-id]
        type = "integer"

        [[pools.vlan-id.ranges]]
        start = "100"
        end = "501"

        [pools.lo-ip]
        ranges = []
        prefix = "10.180.62.1/26"
        type = "ipv4"

        [pools.secondary-vtep-ip]
        ranges = []
        prefix = "10.181.62.1/26"
        type = "ipv4"

        [pools.vni]
        type = "integer"

        [[pools.vni.ranges]]
        start = "1024500"
        end = "1024550"

        [networks.DEV1-C09-DPU-01]
        type = "underlay"
        prefix = "172.20.1.0/24"
        gateway = "172.20.1.1"
        mtu = 1490
        reserve_first = 5

        [networks.admin]
        type = "admin"
        prefix = "172.20.0.0/24"
        gateway = "172.20.0.1"
        mtu = 9000
        reserve_first = 5

        [networks.DEV1-C09-IPMI-01]
        type = "underlay"
        prefix = "127.0.0.0/8"
        gateway = "127.0.0.10"
        mtu = 1490
        reserve_first = 0

        [dpu_nic_firmware_update_version]
        product_x = "v1"

        [ib_fabric_monitor]
        enabled = true
        run_interval = "10s"

        [site_explorer]
        enabled = true
        run_interval = "1s"
        concurrent_explorations = 30
        explorations_per_run = 90
        create_machines = true
        machines_created_per_run = 30
        allow_zero_dpu_hosts = true
        allow_proxy_to_unknown_host = false
        {bmc_proxy_cfg}
        reset_rate_limit = "3600s"

        [machine_state_controller]
        dpu_wait_time = "1s"
        power_down_wait = "1s"
        failure_retry_time = "1s"
        dpu_up_threshold = "31449600s"

        [machine_state_controller.controller]
        iteration_time = "1s"
        processor_dispatch_interval = "500ms"
        max_object_handling_time = "180s"
        max_concurrency = 10

        [network_segment_state_controller]
        network_segment_drain_time = "60s"

        [network_segment_state_controller.controller]
        iteration_time = "2s"
        processor_dispatch_interval = "500ms"
        max_object_handling_time = "180s"
        max_concurrency = 10

        [ib_partition_state_controller.controller]
        iteration_time = "20s"
        processor_dispatch_interval = "2s"
        max_object_handling_time = "180s"
        max_concurrency = 10

        [host_models]

        [firmware_global]
        autoupdate = true
        host_enable_autoupdate = []
        host_disable_autoupdate = []
        run_interval = "5s"
        max_uploads = 4
        concurrency_limit = 16
        firmware_directory = "{firmware_directory_str}"

        [multi_dpu]
        enabled = false

        [host_health]
        hardware_health_reports = "Disabled"

        [measured_boot_collector]
        enabled = true
        run_interval = "10s"

        [machine_validation_config]
        enabled = true
    "#
        )
    };

    carbide::run(
        0,
        carbide_config_str,
        None,
        vault_config,
        true,
        stop_channel,
        ready_channel,
    )
    .await
}
