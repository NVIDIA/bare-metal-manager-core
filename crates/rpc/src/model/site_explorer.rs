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

use model::errors::{OperatorError, OperatorErrorSchema};
use model::site_explorer::{
    BlueFieldOperatingMode, BootOption, BootOrder, Chassis, ComputerSystem,
    ComputerSystemAttributes, EndpointExplorationReport, EthernetInterface, ExploredDpu,
    ExploredEndpoint, ExploredEndpointSearchFilter, ExploredManagedHost,
    ExploredManagedHostSearchFilter, ExploredMlxDevice, InternalLockdownStatus, Inventory,
    LockdownStatus, MachineSetupDiff, MachineSetupStatus, Manager, MlxDeviceKind, NetworkAdapter,
    PCIeDevice, PowerState, SecureBootStatus, Service, SiteExplorationReport, SiteExplorerLastRun,
    SystemStatus,
};

use crate as rpc;

impl From<rpc::site_explorer::ExploredEndpointSearchFilter> for ExploredEndpointSearchFilter {
    fn from(_filter: rpc::site_explorer::ExploredEndpointSearchFilter) -> Self {
        ExploredEndpointSearchFilter {}
    }
}

impl From<rpc::site_explorer::ExploredManagedHostSearchFilter> for ExploredManagedHostSearchFilter {
    fn from(_filter: rpc::site_explorer::ExploredManagedHostSearchFilter) -> Self {
        ExploredManagedHostSearchFilter {}
    }
}

impl From<SystemStatus> for rpc::site_explorer::SystemStatus {
    fn from(status: SystemStatus) -> Self {
        rpc::site_explorer::SystemStatus {
            health: status.health,
            health_rollup: status.health_rollup,
            state: status.state,
        }
    }
}

impl From<PCIeDevice> for rpc::site_explorer::PcIeDevice {
    fn from(device: PCIeDevice) -> Self {
        rpc::site_explorer::PcIeDevice {
            description: device.description,
            firmware_version: device.firmware_version,
            gpu_vendor: device.gpu_vendor,
            id: device.id,
            manufacturer: device.manufacturer,
            name: device.name,
            part_number: device.part_number,
            serial_number: device.serial_number,
            status: device.status.map(Into::into),
        }
    }
}

impl From<ExploredEndpoint> for rpc::site_explorer::ExploredEndpoint {
    fn from(endpoint: ExploredEndpoint) -> Self {
        rpc::site_explorer::ExploredEndpoint {
            address: endpoint.address.to_string(),
            report: Some(endpoint.report.into()),
            report_version: endpoint.report_version.to_string(),
            exploration_requested: endpoint.exploration_requested,
            preingestion_state: format!("{:?}", endpoint.preingestion_state),
            last_redfish_bmc_reset: endpoint
                .last_redfish_bmc_reset
                .map(|time| time.to_string())
                .unwrap_or_else(|| "no timestamp available".to_string()),
            last_ipmitool_bmc_reset: endpoint
                .last_ipmitool_bmc_reset
                .map(|time| time.to_string())
                .unwrap_or_else(|| "no timestamp available".to_string()),
            last_redfish_reboot: endpoint
                .last_redfish_reboot
                .map(|time| time.to_string())
                .unwrap_or_else(|| "no timestamp available".to_string()),
            last_redfish_powercycle: endpoint
                .last_redfish_powercycle
                .map(|time| time.to_string())
                .unwrap_or_else(|| "no timestamp available".to_string()),
            pause_remediation: endpoint.pause_remediation,
        }
    }
}

impl From<&ExploredDpu> for rpc::site_explorer::ExploredDpu {
    fn from(dpu: &ExploredDpu) -> Self {
        rpc::site_explorer::ExploredDpu {
            bmc_ip: dpu.bmc_ip.to_string(),
            host_pf_mac_address: dpu.host_pf_mac_address.map(|m| m.to_string()),
        }
    }
}

impl From<ExploredManagedHost> for rpc::site_explorer::ExploredManagedHost {
    fn from(host: ExploredManagedHost) -> Self {
        rpc::site_explorer::ExploredManagedHost {
            host_bmc_ip: host.host_bmc_ip.to_string(),
            dpus: host
                .dpus
                .iter()
                .map(rpc::site_explorer::ExploredDpu::from)
                .collect(),
            dpu_bmc_ip: host
                .dpus
                .first()
                .map_or("".to_string(), |d| d.bmc_ip.to_string()),
            host_pf_mac_address: host
                .dpus
                .first()
                .and_then(|d| d.host_pf_mac_address.map(|m| m.to_string())),
        }
    }
}

impl From<SiteExplorationReport> for rpc::site_explorer::SiteExplorationReport {
    fn from(report: SiteExplorationReport) -> Self {
        rpc::site_explorer::SiteExplorationReport {
            last_run: report.last_run.map(Into::into),
            endpoints: report.endpoints.into_iter().map(Into::into).collect(),
            managed_hosts: report.managed_hosts.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<SiteExplorerLastRun> for rpc::site_explorer::SiteExplorerLastRun {
    fn from(run: SiteExplorerLastRun) -> Self {
        rpc::site_explorer::SiteExplorerLastRun {
            started_at: run.started_at.to_rfc3339(),
            finished_at: run.finished_at.to_rfc3339(),
            success: run.success,
            error: run.error,
            failure_category: run.failure_category,
            endpoint_explorations: run.endpoint_explorations,
            endpoint_explorations_success: run.endpoint_explorations_success,
            endpoint_explorations_failed: run.endpoint_explorations_failed,
            last_successful_finished_at: run
                .last_successful_finished_at
                .map(|time| time.to_rfc3339()),
            last_failed_finished_at: run.last_failed_finished_at.map(|time| time.to_rfc3339()),
        }
    }
}

impl From<MlxDeviceKind> for rpc::site_explorer::MlxDeviceKind {
    fn from(kind: MlxDeviceKind) -> Self {
        match kind {
            MlxDeviceKind::Bf3NicMode => rpc::site_explorer::MlxDeviceKind::Bf3NicMode,
            MlxDeviceKind::Bf3DpuMode => rpc::site_explorer::MlxDeviceKind::Bf3DpuMode,
            MlxDeviceKind::Bf3SuperNic => rpc::site_explorer::MlxDeviceKind::Bf3SuperNic,
            MlxDeviceKind::Bf2Dpu => rpc::site_explorer::MlxDeviceKind::Bf2Dpu,
            MlxDeviceKind::Unknown => rpc::site_explorer::MlxDeviceKind::Unknown,
        }
    }
}

impl From<BlueFieldOperatingMode> for rpc::site_explorer::BlueFieldOperatingMode {
    fn from(mode: BlueFieldOperatingMode) -> Self {
        match mode {
            BlueFieldOperatingMode::Dpu => Self::Dpu,
            BlueFieldOperatingMode::Nic => Self::Nic,
        }
    }
}

impl From<ExploredMlxDevice> for rpc::site_explorer::ExploredMlxDevice {
    fn from(device: ExploredMlxDevice) -> Self {
        rpc::site_explorer::ExploredMlxDevice {
            host_bmc_ip: device.host_bmc_ip.to_string(),
            machine_id: device.machine_id.map(|id| id.to_string()),
            device_kind: rpc::site_explorer::MlxDeviceKind::from(device.device_kind) as i32,
            pcie_id: device.pcie_id,
            part_number: device.part_number,
            serial_number: device.serial_number,
            firmware_version: device.firmware_version,
            description: device.description,
            dpu_bmc_ip: device.dpu_bmc_ip.map(|ip| ip.to_string()),
            nic_mode: device
                .nic_mode
                .map(|mode| rpc::site_explorer::BlueFieldOperatingMode::from(mode) as i32),
        }
    }
}

impl From<ComputerSystemAttributes> for rpc::site_explorer::ComputerSystemAttributes {
    fn from(attributes: ComputerSystemAttributes) -> Self {
        rpc::site_explorer::ComputerSystemAttributes {
            nic_mode: attributes
                .nic_mode
                .map(|mode| rpc::site_explorer::BlueFieldOperatingMode::from(mode).into()),
        }
    }
}

impl From<ComputerSystem> for rpc::site_explorer::ComputerSystem {
    fn from(system: ComputerSystem) -> Self {
        rpc::site_explorer::ComputerSystem {
            id: system.id,
            manufacturer: system.manufacturer,
            model: system.model,
            serial_number: system.serial_number,
            ethernet_interfaces: system
                .ethernet_interfaces
                .into_iter()
                .map(Into::into)
                .collect(),
            attributes: Some(rpc::site_explorer::ComputerSystemAttributes::from(
                system.attributes,
            )),
            pcie_devices: system.pcie_devices.into_iter().map(Into::into).collect(),
            power_state: rpc::site_explorer::PowerState::from(system.power_state) as _,
            boot_order: system.boot_order.map(|order| order.into()),
        }
    }
}

impl From<PowerState> for rpc::site_explorer::PowerState {
    fn from(state: PowerState) -> Self {
        match state {
            PowerState::Off => rpc::site_explorer::PowerState::Off,
            PowerState::On => rpc::site_explorer::PowerState::On,
            PowerState::PoweringOff => rpc::site_explorer::PowerState::PoweringOff,
            PowerState::PoweringOn => rpc::site_explorer::PowerState::PoweringOn,
            PowerState::Paused => rpc::site_explorer::PowerState::Paused,
            PowerState::Unknown => rpc::site_explorer::PowerState::Unknown,
        }
    }
}

impl From<Manager> for rpc::site_explorer::Manager {
    fn from(manager: Manager) -> Self {
        rpc::site_explorer::Manager {
            id: manager.id,
            ethernet_interfaces: manager
                .ethernet_interfaces
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl From<EthernetInterface> for rpc::site_explorer::EthernetInterface {
    fn from(interface: EthernetInterface) -> Self {
        rpc::site_explorer::EthernetInterface {
            id: interface.id,
            description: interface.description,
            interface_enabled: interface.interface_enabled,
            mac_address: interface.mac_address.map(|mac| mac.to_string()),
            link_status: interface.link_status,
        }
    }
}

impl From<Chassis> for rpc::site_explorer::Chassis {
    fn from(chassis: Chassis) -> Self {
        rpc::site_explorer::Chassis {
            id: chassis.id,
            manufacturer: chassis.manufacturer,
            model: chassis.model,
            part_number: chassis.part_number,
            serial_number: chassis.serial_number,
            network_adapters: chassis
                .network_adapters
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl From<NetworkAdapter> for rpc::site_explorer::NetworkAdapter {
    fn from(adapter: NetworkAdapter) -> Self {
        rpc::site_explorer::NetworkAdapter {
            id: adapter.id,
            manufacturer: adapter.manufacturer,
            model: adapter.model,
            part_number: adapter.part_number,
            serial_number: adapter.serial_number,
        }
    }
}

impl From<SecureBootStatus> for rpc::site_explorer::SecureBootStatus {
    fn from(secure_boot_status: SecureBootStatus) -> Self {
        rpc::site_explorer::SecureBootStatus {
            is_enabled: secure_boot_status.is_enabled,
        }
    }
}

impl From<LockdownStatus> for rpc::site_explorer::LockdownStatus {
    fn from(lockdown_status: LockdownStatus) -> Self {
        rpc::site_explorer::LockdownStatus {
            status: rpc::site_explorer::InternalLockdownStatus::from(lockdown_status.status) as _,
            message: lockdown_status.message,
        }
    }
}

impl From<InternalLockdownStatus> for rpc::site_explorer::InternalLockdownStatus {
    fn from(state: InternalLockdownStatus) -> Self {
        match state {
            InternalLockdownStatus::Enabled => rpc::site_explorer::InternalLockdownStatus::Enabled,
            InternalLockdownStatus::Partial => rpc::site_explorer::InternalLockdownStatus::Partial,
            InternalLockdownStatus::Disabled => {
                rpc::site_explorer::InternalLockdownStatus::Disabled
            }
        }
    }
}

impl From<Service> for rpc::site_explorer::Service {
    fn from(service: Service) -> Self {
        rpc::site_explorer::Service {
            id: service.id,
            inventories: service.inventories.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<Inventory> for rpc::site_explorer::Inventory {
    fn from(inventory: Inventory) -> Self {
        rpc::site_explorer::Inventory {
            id: inventory.id,
            description: inventory.description,
            version: inventory.version,
            release_date: inventory.release_date,
        }
    }
}

impl From<MachineSetupStatus> for rpc::site_explorer::MachineSetupStatus {
    fn from(machine_setup_status: MachineSetupStatus) -> Self {
        rpc::site_explorer::MachineSetupStatus {
            is_done: machine_setup_status.is_done,
            diffs: machine_setup_status
                .diffs
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl From<BootOrder> for rpc::site_explorer::BootOrder {
    fn from(order: BootOrder) -> Self {
        rpc::site_explorer::BootOrder {
            boot_order: order.boot_order.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MachineSetupDiff> for rpc::site_explorer::MachineSetupDiff {
    fn from(machine_setup_diff: MachineSetupDiff) -> Self {
        rpc::site_explorer::MachineSetupDiff {
            key: machine_setup_diff.key,
            expected: machine_setup_diff.expected,
            actual: machine_setup_diff.actual,
        }
    }
}

impl From<BootOption> for rpc::site_explorer::BootOption {
    fn from(boot_option: BootOption) -> Self {
        rpc::site_explorer::BootOption {
            display_name: boot_option.display_name,
            id: boot_option.id,
            boot_option_enabled: boot_option.boot_option_enabled,
            uefi_device_path: boot_option.uefi_device_path,
        }
    }
}

impl From<EndpointExplorationReport> for rpc::site_explorer::EndpointExplorationReport {
    fn from(report: EndpointExplorationReport) -> Self {
        let last_exploration_error_schema = report
            .last_exploration_error
            .as_ref()
            .map(|error| error.operator_error_schema())
            .map(Into::into);

        rpc::site_explorer::EndpointExplorationReport {
            endpoint_type: format!("{:?}", report.endpoint_type),
            last_exploration_error: report.last_exploration_error.map(|error| {
                serde_json::to_string(&error).unwrap_or_else(|_| "Unserializable error".to_string())
            }),
            last_exploration_latency: report.last_exploration_latency.map(Into::into),
            machine_id: report.machine_id.map(|id| id.to_string()),
            vendor: report.vendor.map(|v| v.to_string()),
            managers: report.managers.into_iter().map(Into::into).collect(),
            systems: report.systems.into_iter().map(Into::into).collect(),
            chassis: report.chassis.into_iter().map(Into::into).collect(),
            service: report.service.into_iter().map(Into::into).collect(),
            machine_setup_status: report.machine_setup_status.map(Into::into),
            secure_boot_status: report.secure_boot_status.map(Into::into),
            lockdown_status: report.lockdown_status.map(Into::into),
            firmware_versions: serde_json::to_value(&report.versions)
                .and_then(serde_json::from_value)
                .unwrap_or_default(),
            last_exploration_error_schema,
        }
    }
}

impl From<OperatorErrorSchema> for rpc::site_explorer::OperatorErrorSchema {
    fn from(schema: OperatorErrorSchema) -> Self {
        Self {
            // The wire/proto contract is the rendered `SYSTEM-SUBSYSTEM-CODE` string.
            error_code: schema.error_code.to_string(),
            mitigation: schema.mitigation,
            text: schema.text,
        }
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;
    use model::site_explorer::EndpointExplorationError;
    use prost::Message;

    use super::*;

    #[test]
    fn endpoint_report_propagates_operator_error_schema_to_rpc() {
        let error = EndpointExplorationError::MissingVendor { observed: None };
        let expected_schema = error.operator_error_schema();

        let report =
            rpc::site_explorer::EndpointExplorationReport::from(EndpointExplorationReport {
                last_exploration_error: Some(error),
                ..Default::default()
            });

        let actual_schema = report
            .last_exploration_error_schema
            .expect("report contains operator error schema");
        assert_eq!(
            actual_schema.error_code,
            expected_schema.error_code.to_string()
        );
        assert_eq!(actual_schema.text, expected_schema.text);
        assert_eq!(actual_schema.mitigation, expected_schema.mitigation);
        assert!(report.last_exploration_error.is_some());
    }

    /// Reflection-backed and generated clients retain the legacy protobuf type
    /// while new Rust callers use the observed-state alias.
    #[test]
    fn bluefield_operating_mode_preserves_legacy_protojson_descriptor() {
        let descriptor_set =
            prost_types::FileDescriptorSet::decode(rpc::REFLECTION_API_SERVICE_DESCRIPTOR).unwrap();
        let site_explorer = descriptor_set
            .file
            .iter()
            .find(|file| file.package.as_deref() == Some("site_explorer"))
            .unwrap();

        let operating_mode = site_explorer
            .enum_type
            .iter()
            .find(|enumeration| enumeration.name.as_deref() == Some("NicMode"))
            .unwrap();
        let names_and_numbers = operating_mode
            .value
            .iter()
            .map(|value| (value.name.as_deref().unwrap(), value.number.unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(names_and_numbers, [("DPU", 0), ("NIC", 1)]);

        let explored_device = site_explorer
            .message_type
            .iter()
            .find(|message| message.name.as_deref() == Some("ExploredMlxDevice"))
            .unwrap();
        let mode_field = explored_device
            .field
            .iter()
            .find(|field| field.number == Some(10))
            .unwrap();
        assert_eq!(mode_field.name.as_deref(), Some("nic_mode"));
        assert_eq!(mode_field.json_name.as_deref(), Some("nicMode"));
        assert_eq!(
            mode_field.type_name.as_deref(),
            Some(".site_explorer.NicMode")
        );

        assert_eq!(
            rpc::site_explorer::BlueFieldOperatingMode::Nic.as_str_name(),
            "NIC"
        );
        value_scenarios!(
            run = rpc::site_explorer::BlueFieldOperatingMode::from;
            "DPU mode" {
                BlueFieldOperatingMode::Dpu => rpc::site_explorer::BlueFieldOperatingMode::Dpu,
            }

            "NIC mode" {
                BlueFieldOperatingMode::Nic => rpc::site_explorer::BlueFieldOperatingMode::Nic,
            }
        );
    }
}
