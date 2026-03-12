// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use carbide_uuid::switch::SwitchId;
use tonic::transport::Channel;
use tracing::instrument;

use crate::config::BackendTlsConfig;
use crate::error::ComponentManagerError;
use crate::nv_switch_manager::{
    FirmwareState, NvSwitchManager, SwitchComponentResult, SwitchFirmwareUpdateStatus,
};
use crate::proto::nsm;
use crate::types::PowerAction;

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

fn ids_to_strings(ids: &[SwitchId]) -> Vec<String> {
    ids.iter().map(|id| id.to_string()).collect()
}

fn parse_switch_id(s: &str) -> Result<SwitchId, ComponentManagerError> {
    SwitchId::from_str(s).map_err(|e| {
        ComponentManagerError::Internal(format!("invalid switch id from backend: {e}"))
    })
}

#[async_trait::async_trait]
impl NvSwitchManager for NsmSwitchBackend {
    fn name(&self) -> &str {
        "nsm"
    }

    #[instrument(skip(self), fields(backend = "nsm"))]
    async fn power_control(
        &self,
        ids: &[SwitchId],
        action: PowerAction,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        let nsm_action = match action {
            PowerAction::On => nsm::PowerAction::On,
            PowerAction::GracefulShutdown => nsm::PowerAction::GracefulShutdown,
            PowerAction::ForceOff => nsm::PowerAction::ForceOff,
            PowerAction::GracefulRestart => nsm::PowerAction::GracefulRestart,
            PowerAction::ForceRestart => nsm::PowerAction::ForceRestart,
            PowerAction::AcPowercycle => nsm::PowerAction::PowerCycle,
        };

        let request = nsm::PowerControlRequest {
            uuids: ids_to_strings(ids),
            action: nsm_action as i32,
        };

        let response = self
            .client
            .clone()
            .power_control(request)
            .await?
            .into_inner();

        response
            .responses
            .into_iter()
            .map(|r| {
                Ok(SwitchComponentResult {
                    switch_id: parse_switch_id(&r.uuid)?,
                    success: r.status == nsm::StatusCode::Success as i32,
                    error: if r.error.is_empty() {
                        None
                    } else {
                        Some(r.error)
                    },
                })
            })
            .collect()
    }

    #[instrument(skip(self), fields(backend = "nsm"))]
    async fn queue_firmware_updates(
        &self,
        ids: &[SwitchId],
        bundle_version: &str,
        _components: &[String],
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        let request = nsm::QueueUpdatesRequest {
            switch_uuids: ids_to_strings(ids),
            bundle_version: bundle_version.to_owned(),
            components: vec![],
        };

        let response = self
            .client
            .clone()
            .queue_updates(request)
            .await?
            .into_inner();

        response
            .results
            .into_iter()
            .map(|r| {
                Ok(SwitchComponentResult {
                    switch_id: parse_switch_id(&r.switch_uuid)?,
                    success: r.status == nsm::StatusCode::Success as i32,
                    error: if r.error.is_empty() {
                        None
                    } else {
                        Some(r.error)
                    },
                })
            })
            .collect()
    }

    #[instrument(skip(self), fields(backend = "nsm"))]
    async fn get_firmware_status(
        &self,
        ids: &[SwitchId],
    ) -> Result<Vec<SwitchFirmwareUpdateStatus>, ComponentManagerError> {
        let mut statuses = Vec::new();
        for id in ids {
            let request = nsm::GetUpdatesForSwitchRequest {
                switch_uuid: id.to_string(),
            };
            let response = self
                .client
                .clone()
                .get_updates_for_switch(request)
                .await?
                .into_inner();

            for update in response.updates {
                statuses.push(SwitchFirmwareUpdateStatus {
                    switch_id: parse_switch_id(&update.switch_uuid)?,
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
