/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use api_test_helper::instance;
use api_test_helper::machine_a_tron::MachineATronHandle;
use api_test_helper::utils::REPO_ROOT;
use futures::future::try_join_all;
use machine_a_tron::{HostMachineHandle, MachineATronConfig, MachineConfig};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub struct MachineATronTestHandle {
    _mat_handle: MachineATronHandle,
    pub machines: Vec<HostMachineHandle>,
    pub instance_ids: Vec<String>,
}

pub async fn run(
    host_count: u32,
    api_port: u16,
    admin_dhcp_relay_address: Ipv4Addr,
    instance_segment_id: &str,
    tenant_keyset_ids: &[&str],
) -> eyre::Result<MachineATronTestHandle> {
    let carbide_api_url = format!("https://localhost:{api_port}");
    let mat_config = MachineATronConfig {
        machines: BTreeMap::from([(
            "config".to_string(),
            Arc::new(MachineConfig {
                host_count,
                dpu_per_host_count: 1,
                boot_delay: 1,
                dpu_reboot_delay: 1,
                host_reboot_delay: 1,
                template_dir: REPO_ROOT
                    .join("dev/machine-a-tron/templates")
                    .to_str()
                    .unwrap()
                    .to_string(),
                admin_dhcp_relay_address,
                oob_dhcp_relay_address: Ipv4Addr::new(172, 20, 1, 1),
                vpc_count: 0,
                subnets_per_vpc: 0,
                run_interval_idle: Duration::from_secs(1),
                run_interval_working: Duration::from_millis(100),
                network_status_run_interval: Duration::from_secs(1),
                scout_run_interval: Duration::from_secs(1),
                dpus_in_nic_mode: false,
                dpu_firmware_versions: None,
                dpu_agent_version: None,
            }),
        )]),
        carbide_api_url: carbide_api_url.clone(),
        log_file: None,
        bmc_mock_host_tar: PathBuf::from(format!(
            "{}/dev/bmc-mock/dell_poweredge_r750.tar.gz",
            REPO_ROOT.to_string_lossy(),
        )),
        bmc_mock_dpu_tar: PathBuf::from(format!(
            "{}/dev/bmc-mock/nvidia_dpu.tar.gz",
            REPO_ROOT.to_string_lossy()
        )),
        use_pxe_api: true,
        pxe_server_host: None,
        pxe_server_port: None,
        bmc_mock_port: 443,
        dhcp_server_address: None,
        interface: String::from("lo"),
        tui_enabled: false,
        sudo_command: None,
        use_dhcp_api: true,
        use_single_bmc_mock: false,
        configure_carbide_bmc_proxy_host: None,
        persist_dir: None,
        cleanup_on_quit: false,
        api_refresh_interval: Duration::from_millis(500),
        mock_bmc_ssh_server: true,
    };

    let (machines, mat_handle) =
        api_test_helper::machine_a_tron::run_local(mat_config, vec![], &REPO_ROOT, None).await?;

    let instance_ids = try_join_all(machines.iter().map(|machine| async move {
        machine
            .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(60))
            .await?;

        let machine_id = machine
            .observed_machine_id()
            .expect("Machine ID should be set if host is ready")
            .to_string();
        tracing::info!("Machine {machine_id} has made it to Ready, allocating instance");

        let instance_id = instance::create(
            &[SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                api_port,
            ))],
            &machine_id,
            Some(instance_segment_id),
            None,
            false,
            false,
            tenant_keyset_ids,
        )
        .await?;

        machine
            .wait_until_machine_up_with_api_state("Assigned/Ready", Duration::from_secs(60))
            .await?;

        Ok::<_, eyre::Error>(instance_id)
    }))
    .await?;

    Ok(MachineATronTestHandle {
        _mat_handle: mat_handle,
        machines,
        instance_ids,
    })
}
