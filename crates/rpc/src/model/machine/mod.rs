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
use std::collections::HashSet;
use std::ops::Deref;

use base64::prelude::*;
use carbide_uuid::machine::{MachineId, MachineType};
use health_report::HealthReport;
use model::errors::{ModelError, ModelResult};
use model::machine::{
    DpfState, DpuInfo, DpuInitState, FailureCause, InstanceState, Machine,
    MachineInterfaceSnapshot, MachineValidationFilter, ManagedHostState, ManagedHostStateSnapshot,
    ReprovisionRequest, ReprovisionState, slas, state_sla,
};
use model::machine_interface::InterfaceType;
use model::network_segment::NetworkSegmentType;

use crate as rpc;
use crate::errors::RpcDataConversionError;
use crate::forge_agent_control_response as fac;
use crate::model::RpcTryFrom;
use crate::model::instance::snapshot::instance_snapshot_derive_status;

pub mod capabilities;
pub mod infiniband;
pub mod machine_id;
pub mod machine_search_config;
pub mod network;
pub mod nvlink;
pub mod spx;
pub mod upgrade_policy;

impl From<DpuInfo> for rpc::forge::DpuInfo {
    fn from(info: DpuInfo) -> Self {
        rpc::forge::DpuInfo {
            id: info.id,
            loopback_ip: info.loopback_ip,
        }
    }
}

impl RpcTryFrom<ManagedHostStateSnapshot> for Option<rpc::Instance> {
    type Error = RpcDataConversionError;

    fn rpc_try_from(mut snapshot: ManagedHostStateSnapshot) -> Result<Self, Self::Error> {
        let Some(instance) = snapshot.instance.take() else {
            return Ok(None);
        };

        // TODO: If multiple DPUs have reprovisioning requested, we might not get
        // the expected response
        let mut reprovision_request = snapshot.host_snapshot.reprovision_requested.clone();
        for dpu in &snapshot.dpu_snapshots {
            if let Some(reprovision_requested) = dpu.reprovision_requested.as_ref() {
                reprovision_request = Some(reprovision_requested.clone());
            }
        }
        let (_, dpu_id_to_device_map) = snapshot
            .host_snapshot
            .get_dpu_device_and_id_mappings()
            .map_err(|e| {
                RpcDataConversionError::InvalidValue(
                    "dpu_id_to_device_map".to_string(),
                    e.to_string(),
                )
            })?;
        let status = instance_snapshot_derive_status(
            &instance,
            dpu_id_to_device_map,
            snapshot.managed_state.clone(),
            reprovision_request,
            snapshot
                .host_snapshot
                .infiniband_status_observation
                .as_ref(),
            snapshot.host_snapshot.nvlink_status_observation.as_ref(),
            snapshot.host_snapshot.spx_status_observation.as_ref(),
            &snapshot.host_snapshot.health_reports,
        )?;

        Ok(Some(rpc::Instance {
            id: Some(instance.id),
            machine_id: Some(instance.machine_id),
            config: Some(instance.config.try_into()?),
            status: Some(status.try_into()?),
            config_version: instance.config_version.version_string(),
            network_config_version: instance.network_config_version.version_string(),
            ib_config_version: instance.ib_config_version.version_string(),
            dpu_extension_service_version: instance
                .extension_services_config_version
                .version_string(),
            instance_type_id: instance.instance_type_id.map(|i| i.to_string()),
            metadata: Some(instance.metadata.into()),
            tpm_ek_certificate: snapshot.host_snapshot.hardware_info.and_then(|hi| {
                hi.tpm_ek_certificate
                    .map(|cert| BASE64_STANDARD.encode(cert.into_bytes()))
            }),
            nvlink_config_version: instance.nvlink_config_version.version_string(),
        }))
    }
}

impl From<Machine> for rpc::forge::dpf_state_response::DpfState {
    fn from(value: Machine) -> Self {
        Self {
            machine_id: value.id.into(),
            enabled: value.dpf.enabled,
            used_for_ingestion: value.dpf.used_for_ingestion,
        }
    }
}

pub struct RpcMachineTypeWrapper(rpc::forge::MachineType);

impl From<MachineType> for RpcMachineTypeWrapper {
    fn from(value: MachineType) -> Self {
        RpcMachineTypeWrapper(match value {
            MachineType::PredictedHost | MachineType::Host => rpc::forge::MachineType::Host,
            MachineType::Dpu => rpc::forge::MachineType::Dpu,
        })
    }
}

impl Deref for RpcMachineTypeWrapper {
    type Target = rpc::forge::MachineType;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Machine> for rpc::forge::Machine {
    fn from(mut machine: Machine) -> Self {
        let health = match machine.is_dpu() {
            true => {
                let mut health = machine
                    .dpu_agent_health_report()
                    .cloned()
                    .unwrap_or_else(|| {
                        HealthReport::heartbeat_timeout(
                            HealthReport::DPU_AGENT_SOURCE.to_string(),
                            HealthReport::DPU_AGENT_SOURCE.to_string(),
                            "No health data was received from DPU".to_string(),
                            true,
                            false,
                        )
                    });
                match machine.health_reports.replace.as_ref() {
                    Some(over) => over.clone(),
                    None => {
                        for over in machine
                            .health_reports
                            .merges
                            .iter()
                            .filter(|(source, _)| source.as_str() != HealthReport::DPU_AGENT_SOURCE)
                            .map(|(_, over)| over)
                        {
                            health.merge(over);
                        }
                        health
                    }
                }
            }
            false => HealthReport::empty("aggregate-health".to_string()), // Health is written by ManagedHostStateSnapshot
        };

        let (maintenance_reference, maintenance_start_time) = if !machine.is_dpu() {
            machine
                .health_reports
                .maintenance_override()
                .map(|o| (Some(o.maintenance_reference), o.maintenance_start_time))
                .unwrap_or_default()
        } else {
            (None, None)
        };

        let associated_dpu_machine_ids = machine.associated_dpu_machine_ids();
        let instance_network_restrictions = Some(machine_instance_network_restrictions(&machine));

        rpc::Machine {
            id: Some(machine.id),
            rack_id: machine.rack_id.clone(),
            state: if machine.is_dpu() {
                machine.state.value.dpu_state_string(&machine.id)
            } else {
                machine.state.value.to_string()
            },
            capabilities: machine.to_capabilities().map(|mut c| {
                c.sort();
                c.into()
            }),
            instance_type_id: machine.instance_type_id.map(|i| i.to_string()),
            state_version: machine.state.version.version_string(),
            // calculated at RPC handler, see ManagedHostStateSnapshot::rpc_machine_state
            state_sla: None,
            machine_type: *RpcMachineTypeWrapper::from(machine.id.machine_type()) as _,
            metadata: Some(machine.metadata.into()),
            version: machine.version.version_string(),
            events: machine
                .history
                .into_iter()
                .map(|event| event.into())
                .collect(),
            interfaces: machine
                .interfaces
                .into_iter()
                .map(|interface| interface.into())
                .collect(),
            discovery_info: machine
                .hardware_info
                .and_then(|hw_info| match hw_info.try_into() {
                    Ok(di) => Some(di),
                    Err(e) => {
                        tracing::warn!(
                            machine_id = %machine.id,
                            error = %e,
                            "Hardware information couldn't be parsed into discovery info",
                        );
                        None
                    }
                }),
            bmc_info: Some(machine.bmc_info.into()),
            last_reboot_time: machine.last_reboot_time.map(|t| t.into()),
            last_observation_time: machine
                .network_status_observation
                .as_ref()
                .map(|obs| obs.observed_at.into()),
            dpu_agent_version: machine
                .network_status_observation
                .and_then(|obs| obs.agent_version),
            maintenance_reference,
            maintenance_start_time: maintenance_start_time.map(rpc::Timestamp::from),
            associated_host_machine_id: None, // Gets filled in the `ManagedHostStateSnapshot` conversion
            associated_dpu_machine_ids,
            inventory: Some(machine.inventory.unwrap_or_default().into()),
            last_reboot_requested_time: machine
                .last_reboot_requested
                .as_ref()
                .map(|x| x.time.into()),
            last_reboot_requested_mode: machine.last_reboot_requested.map(|x| x.mode.to_string()),
            state_reason: machine.controller_state_outcome.map(|r| r.into()),
            health: Some(health.into()),
            firmware_autoupdate: machine.firmware_autoupdate,
            health_sources: machine
                .health_reports
                .into_iter()
                .map(|(hr, m)| rpc::forge::HealthSourceOrigin {
                    mode: m as i32,
                    source: hr.source,
                })
                .collect(),
            failure_details: if machine.failure_details.cause != FailureCause::NoError {
                Some(machine.failure_details.to_string())
            } else {
                None
            },
            ib_status: Some(
                machine
                    .infiniband_status_observation
                    .take()
                    .map(|status| status.into())
                    .unwrap_or_default(),
            ),
            instance_network_restrictions,
            hw_sku: machine.hw_sku,
            hw_sku_status: machine.hw_sku_status.map(|s| s.into()),
            quarantine_state: machine
                .network_config
                .quarantine_state
                .take()
                .map(Into::into),
            hw_sku_device_type: machine.hw_sku_device_type,
            update_complete: machine.update_complete,
            nvlink_info: machine.nvlink_info.map(|info| info.into()),
            nvlink_status_observation: machine
                .nvlink_status_observation
                .map(|status| status.into()),
            spx_status_observation: machine.spx_status_observation.map(|status| status.into()),
            placement_in_rack: Some(rpc::forge::PlacementInRack {
                slot_number: machine.slot_number,
                tray_index: machine.tray_index,
            }),
        }
    }
}

impl From<ReprovisionRequest> for rpc::forge::InstanceUpdateStatus {
    fn from(value: ReprovisionRequest) -> Self {
        rpc::forge::InstanceUpdateStatus {
            module: rpc::forge::instance_update_status::Module::Dpu as i32,
            initiator: value.initiator,
            trigger_received_at: Some(value.requested_at.into()),
            update_triggered_at: value.started_at.map(|x| x.into()),
            user_approval_received: value.user_approval_received,
        }
    }
}

impl From<rpc::forge_agent_control_response::MachineValidationFilter> for MachineValidationFilter {
    fn from(filter: rpc::forge_agent_control_response::MachineValidationFilter) -> Self {
        Self {
            tags: filter.tags,
            allowed_tests: filter.allowed_tests,
            run_unverfied_tests: filter.run_unverfied_tests,
            contexts: filter.contexts.map(|c| c.items),
        }
    }
}

impl From<MachineValidationFilter> for fac::MachineValidationFilter {
    fn from(filter: MachineValidationFilter) -> Self {
        Self {
            tags: filter.tags,
            allowed_tests: filter.allowed_tests,
            run_unverfied_tests: filter.run_unverfied_tests,
            contexts: filter
                .contexts
                .map(|items| rpc::common::StringList { items }),
        }
    }
}

pub fn get_action_for_dpu_state(
    state: &ManagedHostState,
    dpu_machine_id: &MachineId,
) -> ModelResult<fac::Action> {
    Ok(match state {
        ManagedHostState::DPUReprovision { .. }
        | ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision { .. },
        } => {
            let dpu_state = state
                .as_reprovision_state(dpu_machine_id)
                .ok_or(ModelError::MissingDpu(*dpu_machine_id))?;
            match dpu_state {
                ReprovisionState::BufferTime => fac::Action::retry(),
                ReprovisionState::WaitingForNetworkInstall
                | ReprovisionState::DpfStates {
                    substate: DpfState::WaitingForReady { .. },
                } => fac::Action::Discovery(fac::Discovery {}),
                _ => {
                    tracing::info!(
                        dpu_machine_id = %dpu_machine_id,
                        machine_type = "DPU",
                        %state,
                        "forge agent control",
                    );
                    fac::Action::noop()
                }
            }
        }
        ManagedHostState::DPUInit { dpu_states } => {
            let dpu_state = dpu_states
                .states
                .get(dpu_machine_id)
                .ok_or(ModelError::MissingDpu(*dpu_machine_id))?;

            match dpu_state {
                DpuInitState::Init
                | DpuInitState::DpfStates {
                    state: DpfState::WaitingForReady { .. },
                } => fac::Action::Discovery(fac::Discovery {}),
                _ => {
                    tracing::info!(
                        dpu_machine_id = %dpu_machine_id,
                        machine_type = "DPU",
                        %state,
                        "forge agent control",
                    );
                    fac::Action::noop()
                }
            }
        }
        _ => {
            // Later this might go to site admin dashboard for manual intervention
            tracing::info!(
                dpu_machine_id = %dpu_machine_id,
                machine_type = "DPU",
                %state,
                "forge agent control",
            );
            fac::Action::noop()
        }
    })
}

impl From<MachineInterfaceSnapshot> for rpc::MachineInterface {
    #[allow(deprecated)]
    fn from(machine_interface: MachineInterfaceSnapshot) -> rpc::MachineInterface {
        let is_bmc = machine_interface.interface_type == InterfaceType::Bmc;

        rpc::MachineInterface {
            id: Some(machine_interface.id),
            attached_dpu_machine_id: machine_interface.attached_dpu_machine_id,
            machine_id: machine_interface.machine_id,
            segment_id: Some(machine_interface.segment_id),
            hostname: machine_interface.hostname,
            domain_id: machine_interface.domain_id,
            mac_address: machine_interface.mac_address.to_string(),
            primary_interface: machine_interface.primary_interface,
            address: machine_interface
                .addresses
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
            vendor: machine_interface.vendors.last().cloned(),
            created: Some(machine_interface.created.into()),
            last_dhcp: machine_interface.last_dhcp.map(|t| t.into()),
            power_shelf_id: machine_interface.power_shelf_id,
            is_bmc: Some(is_bmc),
            interface_type: Some(machine_interface.interface_type as i32),
            switch_id: machine_interface.switch_id,
            association_type: machine_interface.association_type.map(|t| t as i32),
        }
    }
}

pub trait ManagedHostStateSnapshotRpc {
    fn rpc_machine_state(
        &self,
        dpu_machine_id: Option<&MachineId>,
        sla_config: &slas::MachineSlaConfig,
    ) -> Option<rpc::forge::Machine>;
}

impl ManagedHostStateSnapshotRpc for ManagedHostStateSnapshot {
    /// Creates an RPC Machine representation for either the Host or one of the DPUs
    fn rpc_machine_state(
        &self,
        dpu_machine_id: Option<&MachineId>,
        sla_config: &slas::MachineSlaConfig,
    ) -> Option<rpc::forge::Machine> {
        match dpu_machine_id {
            None => {
                let mut rpc_machine: rpc::forge::Machine = self.host_snapshot.clone().into();
                let state = &self.host_snapshot.state.value;
                let version = &self.host_snapshot.state.version;
                rpc_machine.health = Some(self.aggregate_health.clone().into());
                rpc_machine.state_sla = Some(
                    state_sla(
                        &self.host_snapshot.id,
                        state,
                        version,
                        &self.aggregate_health,
                        sla_config,
                    )
                    .into(),
                );
                Some(rpc_machine)
            }
            Some(dpu_machine_id) => {
                let dpu_snapshot = self
                    .dpu_snapshots
                    .iter()
                    .find(|dpu| dpu.id == *dpu_machine_id)?;
                let mut rpc_machine: rpc::forge::Machine = dpu_snapshot.clone().into();
                // In case the DPU does not know the associated Host - we can backfill the data here
                rpc_machine.associated_host_machine_id = Some(self.host_snapshot.id);
                rpc_machine.state_sla = Some(
                    state_sla(
                        &dpu_snapshot.id,
                        &dpu_snapshot.state.value,
                        &dpu_snapshot.state.version,
                        &self.aggregate_health,
                        sla_config,
                    )
                    .into(),
                );
                Some(rpc_machine)
            }
        }
    }
}

fn machine_instance_network_restrictions(
    machine: &Machine,
) -> rpc::forge::InstanceNetworkRestrictions {
    let inband_interfaces = machine
        .interfaces
        .iter()
        .filter(|i| matches!(i.network_segment_type, Some(NetworkSegmentType::HostInband)))
        .collect::<Vec<_>>();

    // If there are no HostInband interfaces, this currently means this machine has DPUs and is
    // not restricted to being in particular network segments
    if inband_interfaces.is_empty() {
        return rpc::forge::InstanceNetworkRestrictions {
            network_segment_membership_type:
                rpc::forge::InstanceNetworkSegmentMembershipType::TenantConfigurable as i32,
            network_segment_ids: vec![],
        };
    }

    // The machine has interfaces on HostInband segments, meaning its network segment
    // memebership is static (cannot be configured at instance allocation time.)

    // Get unique segment ID's and VPC ID's from each HostInband interface
    let inband_network_segment_ids = inband_interfaces
        .iter()
        .map(|iface| iface.segment_id)
        .collect::<HashSet<_>>();

    rpc::forge::InstanceNetworkRestrictions {
        network_segment_membership_type: rpc::forge::InstanceNetworkSegmentMembershipType::Static
            as i32,
        network_segment_ids: inband_network_segment_ids.into_iter().collect(),
    }
}

#[cfg(test)]
mod test {
    use crate as rpc;
    use crate::model::machine::DpuInfo;

    #[test]
    fn dpu_info_to_rpc() {
        let info = DpuInfo {
            id: "dpu-123".to_string(),
            loopback_ip: "10.0.0.1".to_string(),
        };
        let rpc_info: rpc::forge::DpuInfo = info.into();
        assert_eq!(rpc_info.id, "dpu-123");
        assert_eq!(rpc_info.loopback_ip, "10.0.0.1");
    }
}
