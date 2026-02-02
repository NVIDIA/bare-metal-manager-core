/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use libredfish::RoleId;
use libredfish::model::oem::nvidia_dpu::NicMode;
use mac_address::MacAddress;
use model::expected_machine::ExpectedMachine;
use model::expected_power_shelf::ExpectedPowerShelf;
use model::expected_switch::ExpectedSwitch;
use model::machine::MachineInterfaceSnapshot;
use model::site_explorer::{
    EndpointExplorationError, EndpointExplorationReport, InternalLockdownStatus, LockdownStatus,
};

use crate::site_explorer::{EndpointExplorer, SiteExplorationMetrics};

/// EndpointExplorer which returns predefined data
#[derive(Clone, Default, Debug)]
pub struct MockEndpointExplorer {
    pub reports:
        Arc<Mutex<HashMap<IpAddr, Result<EndpointExplorationReport, EndpointExplorationError>>>>,
}

impl MockEndpointExplorer {
    pub fn insert_endpoints(&self, endpoints: Vec<(IpAddr, EndpointExplorationReport)>) {
        self.insert_endpoint_results(
            endpoints
                .into_iter()
                .map(|(addr, report)| (addr, Ok(report)))
                .collect(),
        )
    }

    pub fn insert_endpoint_result(
        &self,
        address: IpAddr,
        result: Result<EndpointExplorationReport, EndpointExplorationError>,
    ) {
        self.insert_endpoint_results(vec![(address, result)]);
    }

    pub fn insert_endpoint_results(
        &self,
        endpoints: Vec<(
            IpAddr,
            Result<EndpointExplorationReport, EndpointExplorationError>,
        )>,
    ) {
        let mut guard = self.reports.lock().unwrap();
        for (address, result) in endpoints {
            guard.insert(address, result);
        }
    }
}

#[async_trait::async_trait]
impl EndpointExplorer for MockEndpointExplorer {
    async fn check_preconditions(
        &self,
        _metrics: &mut SiteExplorationMetrics,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }
    async fn explore_endpoint(
        &self,
        bmc_ip_address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _expected: Option<&ExpectedMachine>,
        _expected_power_shelf: Option<&ExpectedPowerShelf>,
        _expected_switch: Option<&ExpectedSwitch>,
        _last_report: Option<&EndpointExplorationReport>,
        _boot_interface_mac: Option<MacAddress>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        tracing::info!("Endpoint {bmc_ip_address} is getting explored");
        let guard = self.reports.lock().unwrap();
        let res = guard.get(&bmc_ip_address.ip()).unwrap();
        res.clone()
    }

    async fn redfish_reset_bmc(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn ipmitool_reset_bmc(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn redfish_power_control(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _action: libredfish::SystemPowerControl,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn have_credentials(&self, _interface: &MachineInterfaceSnapshot) -> bool {
        true
    }

    async fn disable_secure_boot(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn lockdown(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _action: libredfish::EnabledDisabled,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn lockdown_status(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<LockdownStatus, EndpointExplorationError> {
        Ok(LockdownStatus {
            status: InternalLockdownStatus::Disabled,
            message: "".to_string(),
        })
    }

    async fn machine_setup(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _boot_interface_mac: Option<&str>,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn set_boot_order_dpu_first(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _boot_interface_mac: &str,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn set_nic_mode(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _mode: NicMode,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn is_viking(
        &self,
        _bmc_ip_address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<bool, EndpointExplorationError> {
        Ok(false)
    }

    async fn clear_nvram(
        &self,
        _bmc_ip_address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn copy_bfb_to_dpu_rshim(
        &self,
        _bmc_ip_address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn create_bmc_user(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _username: &str,
        _password: &str,
        _role_id: RoleId,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn delete_bmc_user(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _username: &str,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn enable_infinite_boot(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn is_infinite_boot_enabled(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<Option<bool>, EndpointExplorationError> {
        Ok(None)
    }

    async fn probe_redfish_endpoint(
        &self,
        _address: SocketAddr,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }
}
