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

use carbide_host_support::agent_config::MachineIdentityConfig;
use eyre::eyre;
use forge_dpu_fmds_shared::machine_identity::MachineIdentityParams;
use rpc::fmds::fmds_config_service_client::FmdsConfigServiceClient;
use rpc::fmds::{
    FmdsConfigUpdate, FmdsMachineIdentityConfig, IbDevice, IbInstance, UpdateConfigRequest,
};
use rpc::forge::ManagedHostNetworkConfigResponse;
use tonic::transport::Channel;

use crate::instance_metadata_endpoint::InstanceMetadataRouterStateImpl;
use crate::periodic_config_fetcher::InstanceMetadata;

/// FmdsUpdater abstracts over embedded vs external FMDS
/// updates so the main loop doesn't need to care which
/// mode it's in. It's all handled in here.
pub enum FmdsUpdater {
    /// Embedded will update FMDS state directly within the
    /// carbide-dpu-agent (because the FMDS listener is in
    /// the agent).
    Embedded(Arc<InstanceMetadataRouterStateImpl>),
    /// External will send FMDS updates to an FMDS server,
    /// which is colocated on the same DPU, possibly in its
    /// own container.
    External(Box<FmdsGrpcClient>),
}

impl FmdsUpdater {
    pub async fn update(
        &mut self,
        instance_data: Option<Arc<InstanceMetadata>>,
        network_config: Option<Arc<ManagedHostNetworkConfigResponse>>,
    ) {
        match self {
            FmdsUpdater::Embedded(state) => {
                state.update_instance_data(instance_data);
                state.update_network_configuration(network_config);
            }
            FmdsUpdater::External(client) => {
                if let Err(err) = client.update_config(&instance_data, &network_config).await {
                    tracing::error!(
                        error = format!("{err:#}"),
                        fmds_address = client.address,
                        "Failed to send config update to external FMDS"
                    );
                }
            }
        }
    }
}

pub struct FmdsGrpcClient {
    client: FmdsConfigServiceClient<Channel>,
    address: String,
    machine_identity: MachineIdentityConfig,
}

impl FmdsGrpcClient {
    pub async fn connect(
        address: &str,
        machine_identity: MachineIdentityConfig,
    ) -> eyre::Result<Self> {
        let client = FmdsConfigServiceClient::connect(address.to_string()).await?;
        Ok(Self {
            client,
            address: address.to_string(),
            machine_identity,
        })
    }

    fn machine_identity_proto(&self) -> eyre::Result<FmdsMachineIdentityConfig> {
        MachineIdentityParams::try_from_limits(
            self.machine_identity.requests_per_second,
            self.machine_identity.burst,
            self.machine_identity.wait_timeout_secs,
            self.machine_identity.sign_timeout_secs,
            self.machine_identity.sign_proxy_url.as_deref(),
            self.machine_identity.sign_proxy_tls_root_ca.as_deref(),
        )
        .map(Into::into)
        .map_err(|msg| eyre!("machine-identity (FMDS config push): {msg}"))
    }

    async fn update_config(
        &mut self,
        instance_data: &Option<Arc<InstanceMetadata>>,
        network_config: &Option<Arc<ManagedHostNetworkConfigResponse>>,
    ) -> eyre::Result<()> {
        let Some(metadata) = instance_data else {
            return Ok(());
        };

        let asn = network_config.as_ref().map(|c| c.asn).unwrap_or(0);

        let ib_devices = metadata
            .ib_devices
            .as_ref()
            .map(|devices| {
                devices
                    .iter()
                    .map(|dev| IbDevice {
                        pf_guid: dev.pf_guid.clone(),
                        instances: dev
                            .instances
                            .iter()
                            .map(|inst| IbInstance {
                                ib_partition_id: inst
                                    .ib_partition_id
                                    .as_ref()
                                    .map(|id| id.to_string()),
                                ib_guid: inst.ib_guid.clone(),
                                lid: inst.lid,
                            })
                            .collect(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let update = FmdsConfigUpdate {
            address: metadata.address.clone(),
            hostname: metadata.hostname.clone(),
            sitename: metadata.sitename.clone(),
            instance_id: metadata.instance_id,
            machine_id: metadata.machine_id,
            user_data: metadata.user_data.clone(),
            ib_devices,
            asn,
            machine_identity: Some(self.machine_identity_proto()?),
        };

        self.client
            .update_config(tonic::Request::new(UpdateConfigRequest {
                config_update: Some(update),
            }))
            .await?;

        tracing::debug!(
            fmds_address = self.address,
            "Sent config update to external FMDS"
        );

        Ok(())
    }
}
