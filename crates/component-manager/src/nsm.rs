// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use mac_address::MacAddress;
use tonic::transport::Channel;
use tracing::instrument;

use crate::config::BackendTlsConfig;
use crate::error::ComponentManagerError;
use crate::nv_switch_manager::{
    NvSwitchManager, SwitchComponentResult, SwitchEndpoint, SwitchFirmwareUpdateStatus,
};
use crate::proto::nsm;
use crate::types::{FirmwareState, NvSwitchComponent, PowerAction, parse_mac};

#[derive(Debug)]
pub struct NsmSwitchBackend {
    client: nsm::nv_switch_manager_client::NvSwitchManagerClient<Channel>,
}

impl NsmSwitchBackend {
    pub async fn connect(
        url: &str,
        tls: Option<&BackendTlsConfig>,
    ) -> Result<Self, ComponentManagerError> {
        let channel = crate::tls::build_channel(url, tls, "NSM").await?;
        Ok(Self {
            client: nsm::nv_switch_manager_client::NvSwitchManagerClient::new(channel),
        })
    }
}

fn to_nsm_component(c: &NvSwitchComponent) -> nsm::NvSwitchComponent {
    match c {
        NvSwitchComponent::Bmc => nsm::NvSwitchComponent::NvswitchComponentBmc,
        NvSwitchComponent::Cpld => nsm::NvSwitchComponent::NvswitchComponentCpld,
        NvSwitchComponent::Bios => nsm::NvSwitchComponent::NvswitchComponentBios,
        NvSwitchComponent::Nvos => nsm::NvSwitchComponent::NvswitchComponentNvos,
    }
}

fn map_nsm_update_state(state: i32) -> FirmwareState {
    match nsm::UpdateState::try_from(state) {
        Ok(nsm::UpdateState::Queued) => FirmwareState::Queued,
        Ok(nsm::UpdateState::Copy)
        | Ok(nsm::UpdateState::Upload)
        | Ok(nsm::UpdateState::Install)
        | Ok(nsm::UpdateState::PollCompletion)
        | Ok(nsm::UpdateState::PowerCycle)
        | Ok(nsm::UpdateState::WaitReachable) => FirmwareState::InProgress,
        Ok(nsm::UpdateState::Verify) | Ok(nsm::UpdateState::Cleanup) => FirmwareState::Verifying,
        Ok(nsm::UpdateState::Completed) => FirmwareState::Completed,
        Ok(nsm::UpdateState::Failed) => FirmwareState::Failed,
        Ok(nsm::UpdateState::Cancelled) => FirmwareState::Cancelled,
        _ => FirmwareState::Unknown,
    }
}

/// Builds a single registration request for an endpoint.
fn build_registration(ep: &SwitchEndpoint) -> nsm::RegisterNvSwitchRequest {
    nsm::RegisterNvSwitchRequest {
        vendor: nsm::Vendor::Nvidia as i32,
        bmc: Some(nsm::Subsystem {
            mac_address: ep.bmc_mac.to_string(),
            ip_address: ep.bmc_ip.to_string(),
            credentials: None,
            port: 0,
        }),
        nvos: Some(nsm::Subsystem {
            mac_address: ep.nvos_mac.to_string(),
            ip_address: ep.nvos_ip.to_string(),
            credentials: None,
            port: 0,
        }),
        rack_id: String::new(),
    }
}

/// Registers endpoints with NSM one at a time and returns bidirectional
/// maps between BMC MAC and NSM-generated UUID.
///
/// Each endpoint is registered individually to avoid relying on response
/// ordering from the batch API. This can be switched back to batch
/// registration once NSM includes a correlation key (e.g. BMC MAC) in
/// RegisterNVSwitchResponse.
async fn register_and_map(
    client: &mut nsm::nv_switch_manager_client::NvSwitchManagerClient<Channel>,
    endpoints: &[SwitchEndpoint],
) -> Result<(HashMap<MacAddress, String>, HashMap<String, MacAddress>), ComponentManagerError> {
    let mut mac_to_uuid: HashMap<MacAddress, String> = HashMap::new();
    let mut uuid_to_mac: HashMap<String, MacAddress> = HashMap::new();

    for ep in endpoints {
        let req = build_registration(ep);
        let response = client
            .register_nv_switches(nsm::RegisterNvSwitchesRequest {
                registration_requests: vec![req],
            })
            .await?
            .into_inner();

        let Some(reg_resp) = response.responses.into_iter().next() else {
            tracing::warn!(bmc_mac = %ep.bmc_mac, "NSM returned empty response for switch");
            continue;
        };

        if reg_resp.status != nsm::StatusCode::Success as i32 {
            tracing::warn!(
                bmc_mac = %ep.bmc_mac,
                error = %reg_resp.error,
                "NSM registration failed for switch"
            );
            continue;
        }

        mac_to_uuid.insert(ep.bmc_mac, reg_resp.uuid.clone());
        uuid_to_mac.insert(reg_resp.uuid.clone(), ep.bmc_mac);
    }

    if mac_to_uuid.is_empty() && !endpoints.is_empty() {
        return Err(ComponentManagerError::Internal(
            "NSM registration failed for all switches".into(),
        ));
    }

    Ok((mac_to_uuid, uuid_to_mac))
}

#[async_trait::async_trait]
impl NvSwitchManager for NsmSwitchBackend {
    fn name(&self) -> &str {
        "nsm"
    }

    #[instrument(skip(self), fields(backend = "nsm"))]
    async fn power_control(
        &self,
        endpoints: &[SwitchEndpoint],
        action: PowerAction,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        let (mac_to_uuid, uuid_to_mac) =
            register_and_map(&mut self.client.clone(), endpoints).await?;

        let mut results: Vec<SwitchComponentResult> = Vec::new();
        let mut uuids: Vec<String> = Vec::new();

        for ep in endpoints {
            match mac_to_uuid.get(&ep.bmc_mac) {
                Some(uuid) => uuids.push(uuid.clone()),
                None => results.push(SwitchComponentResult {
                    bmc_mac: ep.bmc_mac,
                    success: false,
                    error: Some("NSM registration failed for switch".into()),
                }),
            }
        }

        let nsm_action = match action {
            PowerAction::On => nsm::PowerAction::On,
            PowerAction::GracefulShutdown => nsm::PowerAction::GracefulShutdown,
            PowerAction::ForceOff => nsm::PowerAction::ForceOff,
            PowerAction::GracefulRestart => nsm::PowerAction::GracefulRestart,
            PowerAction::ForceRestart => nsm::PowerAction::ForceRestart,
            PowerAction::AcPowercycle => nsm::PowerAction::PowerCycle,
        };

        if !uuids.is_empty() {
            let request = nsm::PowerControlRequest {
                uuids,
                action: nsm_action as i32,
            };

            let response = self
                .client
                .clone()
                .power_control(request)
                .await?
                .into_inner();

            for r in response.responses {
                let bmc_mac = uuid_to_mac
                    .get(&r.uuid)
                    .copied()
                    .map(Ok)
                    .unwrap_or_else(|| parse_mac(&r.uuid))?;
                results.push(SwitchComponentResult {
                    bmc_mac,
                    success: r.status == nsm::StatusCode::Success as i32,
                    error: if r.error.is_empty() {
                        None
                    } else {
                        Some(r.error)
                    },
                });
            }
        }

        Ok(results)
    }

    #[instrument(skip(self), fields(backend = "nsm"))]
    async fn queue_firmware_updates(
        &self,
        endpoints: &[SwitchEndpoint],
        bundle_version: &str,
        components: &[NvSwitchComponent],
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        let (mac_to_uuid, uuid_to_mac) =
            register_and_map(&mut self.client.clone(), endpoints).await?;

        let mut results: Vec<SwitchComponentResult> = Vec::new();
        let mut uuids: Vec<String> = Vec::new();

        for ep in endpoints {
            match mac_to_uuid.get(&ep.bmc_mac) {
                Some(uuid) => uuids.push(uuid.clone()),
                None => results.push(SwitchComponentResult {
                    bmc_mac: ep.bmc_mac,
                    success: false,
                    error: Some("NSM registration failed for switch".into()),
                }),
            }
        }

        if !uuids.is_empty() {
            let nsm_components: Vec<i32> = components
                .iter()
                .map(|c| to_nsm_component(c) as i32)
                .collect();

            let request = nsm::QueueUpdatesRequest {
                switch_uuids: uuids,
                bundle_version: bundle_version.to_owned(),
                components: nsm_components,
            };

            let response = self
                .client
                .clone()
                .queue_updates(request)
                .await?
                .into_inner();

            for r in response.results {
                let bmc_mac = uuid_to_mac
                    .get(&r.switch_uuid)
                    .copied()
                    .map(Ok)
                    .unwrap_or_else(|| parse_mac(&r.switch_uuid))?;
                results.push(SwitchComponentResult {
                    bmc_mac,
                    success: r.status == nsm::StatusCode::Success as i32,
                    error: if r.error.is_empty() {
                        None
                    } else {
                        Some(r.error)
                    },
                });
            }
        }

        Ok(results)
    }

    #[instrument(skip(self), fields(backend = "nsm"))]
    async fn get_firmware_status(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchFirmwareUpdateStatus>, ComponentManagerError> {
        let (mac_to_uuid, uuid_to_mac) =
            register_and_map(&mut self.client.clone(), endpoints).await?;

        let mut statuses = Vec::new();

        for ep in endpoints {
            let Some(uuid) = mac_to_uuid.get(&ep.bmc_mac) else {
                statuses.push(SwitchFirmwareUpdateStatus {
                    bmc_mac: ep.bmc_mac,
                    state: FirmwareState::Unknown,
                    target_version: String::new(),
                    error: Some("NSM registration failed for switch".into()),
                });
                continue;
            };

            let request = nsm::GetUpdatesForSwitchRequest {
                switch_uuid: uuid.clone(),
            };
            let response = self
                .client
                .clone()
                .get_updates_for_switch(request)
                .await?
                .into_inner();

            for update in response.updates {
                let bmc_mac = uuid_to_mac
                    .get(&update.switch_uuid)
                    .copied()
                    .unwrap_or(ep.bmc_mac);
                statuses.push(SwitchFirmwareUpdateStatus {
                    bmc_mac,
                    state: map_nsm_update_state(update.state),
                    target_version: update.version_to,
                    error: if update.error_message.is_empty() {
                        None
                    } else {
                        Some(update.error_message)
                    },
                });
            }
        }
        Ok(statuses)
    }

    #[instrument(skip(self), fields(backend = "nsm"))]
    async fn list_firmware_bundles(&self) -> Result<Vec<String>, ComponentManagerError> {
        let response = self.client.clone().list_bundles(()).await?.into_inner();

        Ok(response.bundles.into_iter().map(|b| b.version).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsm_state_queued() {
        assert_eq!(
            map_nsm_update_state(nsm::UpdateState::Queued as i32),
            FirmwareState::Queued,
        );
    }

    #[test]
    fn nsm_state_in_progress_variants() {
        for state in [
            nsm::UpdateState::Copy,
            nsm::UpdateState::Upload,
            nsm::UpdateState::Install,
            nsm::UpdateState::PollCompletion,
            nsm::UpdateState::PowerCycle,
            nsm::UpdateState::WaitReachable,
        ] {
            assert_eq!(
                map_nsm_update_state(state as i32),
                FirmwareState::InProgress,
                "expected InProgress for {state:?}",
            );
        }
    }

    #[test]
    fn nsm_state_verifying_variants() {
        for state in [nsm::UpdateState::Verify, nsm::UpdateState::Cleanup] {
            assert_eq!(
                map_nsm_update_state(state as i32),
                FirmwareState::Verifying,
                "expected Verifying for {state:?}",
            );
        }
    }

    #[test]
    fn nsm_state_completed() {
        assert_eq!(
            map_nsm_update_state(nsm::UpdateState::Completed as i32),
            FirmwareState::Completed,
        );
    }

    #[test]
    fn nsm_state_failed() {
        assert_eq!(
            map_nsm_update_state(nsm::UpdateState::Failed as i32),
            FirmwareState::Failed,
        );
    }

    #[test]
    fn nsm_state_cancelled() {
        assert_eq!(
            map_nsm_update_state(nsm::UpdateState::Cancelled as i32),
            FirmwareState::Cancelled,
        );
    }

    #[test]
    fn nsm_state_unknown_for_unrecognized_value() {
        assert_eq!(map_nsm_update_state(9999), FirmwareState::Unknown);
    }

    #[test]
    fn build_registration_populates_fields() {
        let ep = SwitchEndpoint {
            bmc_ip: "10.0.0.1".parse().unwrap(),
            bmc_mac: "AA:BB:CC:DD:EE:01".parse().unwrap(),
            nvos_ip: "10.0.0.2".parse().unwrap(),
            nvos_mac: "AA:BB:CC:DD:EE:02".parse().unwrap(),
        };
        let req = build_registration(&ep);
        assert_eq!(req.vendor, nsm::Vendor::Nvidia as i32);

        let bmc = req.bmc.as_ref().unwrap();
        assert_eq!(bmc.ip_address, "10.0.0.1");
        assert_eq!(bmc.mac_address, "AA:BB:CC:DD:EE:01");

        let nvos = req.nvos.as_ref().unwrap();
        assert_eq!(nvos.ip_address, "10.0.0.2");
        assert_eq!(nvos.mac_address, "AA:BB:CC:DD:EE:02");
    }

    #[test]
    fn to_nsm_component_all_variants() {
        assert_eq!(
            to_nsm_component(&NvSwitchComponent::Bmc),
            nsm::NvSwitchComponent::NvswitchComponentBmc
        );
        assert_eq!(
            to_nsm_component(&NvSwitchComponent::Cpld),
            nsm::NvSwitchComponent::NvswitchComponentCpld
        );
        assert_eq!(
            to_nsm_component(&NvSwitchComponent::Bios),
            nsm::NvSwitchComponent::NvswitchComponentBios
        );
        assert_eq!(
            to_nsm_component(&NvSwitchComponent::Nvos),
            nsm::NvSwitchComponent::NvswitchComponentNvos
        );
    }
}
