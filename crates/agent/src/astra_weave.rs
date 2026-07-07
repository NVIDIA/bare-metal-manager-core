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

use std::collections::{HashMap, HashSet};

use ::rpc::forge::{
    AstraAttachmentStatus, AstraConfig, AstraConfigStatus, AstraPhase, AstraStatus,
    SpxAttachmentType,
};
use eyre::WrapErr;

use crate::weave_ew_vpc_client::proto::state::Phase;
use crate::weave_ew_vpc_client::proto::{
    AttachmentOvn, AttachmentPf, AttachmentType, AttachmentVf,
    CreateVirtualNetworkAttachmentRequest, CreateVirtualNetworkRequest,
    DeleteVirtualNetworkAttachmentRequest, DeleteVirtualNetworkRequest,
    ListVirtualNetworkAttachmentsRequest, ListVirtualNetworksRequest, ObjectMetadata, State,
    VirtualNetworkAttachment, VirtualNetworkAttachmentSpec, VirtualNetworkSpec,
};
use crate::weave_ew_vpc_client::{
    WEAVE_EW_VPC_FLOW_CONTROLLER_SOCKET_PATH, weave_ew_vpc_create_virtual_network,
    weave_ew_vpc_create_virtual_network_attachment, weave_ew_vpc_delete_virtual_network,
    weave_ew_vpc_delete_virtual_network_attachment, weave_ew_vpc_list_virtual_network_attachments,
    weave_ew_vpc_list_virtual_networks,
};

fn astra_weave_ew_vpc_virtual_network_id(vni: i32) -> String {
    format!("astra-weave-vni-{vni}")
}

fn astra_attachment_weave_ew_vpc_spec(
    astra_attachment_status: &AstraAttachmentStatus,
) -> Result<VirtualNetworkAttachmentSpec, State> {
    let Some(astra_attachment_type) = astra_attachment_status.attachment_type else {
        return Err(State {
            phase: Phase::Error.into(),
            reason: "Missing Astra SpxAttachmentType".to_string(),
            message: "create_virtual_network_attachment".to_string(),
        });
    };

    let astra_attachment_type =
        SpxAttachmentType::try_from(astra_attachment_type).map_err(|_| State {
            phase: Phase::Error.into(),
            reason: "Unknown Astra SpxAttachmentType".to_string(),
            message: "create_virtual_network_attachment".to_string(),
        })?;

    let mut spec = VirtualNetworkAttachmentSpec {
        vnet_id: astra_weave_ew_vpc_virtual_network_id(astra_attachment_status.vni),
        nic_id: astra_attachment_status.mac_address.clone(),
        attachment_type: AttachmentType::Unspecified.into(),
        attachment_pf: None,
        attachment_vf: None,
        attachment_ovn: None,
    };

    match astra_attachment_type {
        SpxAttachmentType::Physical => {
            spec.attachment_type = AttachmentType::Pf.into();
            spec.attachment_pf = Some(AttachmentPf {
                pf_id: astra_attachment_status.mac_address.clone(),
            });
        }
        SpxAttachmentType::Virtual => {
            let Some(virtual_function_id) = astra_attachment_status.virtual_function_id else {
                return Err(State {
                    phase: Phase::Error.into(),
                    reason: "Missing Astra virtual_function_id".to_string(),
                    message: "create_virtual_network_attachment".to_string(),
                });
            };
            let Ok(vf_index) = u32::try_from(virtual_function_id) else {
                return Err(State {
                    phase: Phase::Error.into(),
                    reason: "Invalid Astra virtual_function_id".to_string(),
                    message: "create_virtual_network_attachment".to_string(),
                });
            };

            spec.attachment_type = AttachmentType::Vf.into();
            spec.attachment_vf = Some(AttachmentVf {
                pf_id: astra_attachment_status.mac_address.clone(),
                vf_index,
            });
        }
        SpxAttachmentType::Ovn => {
            let Some(network_name) = astra_attachment_status
                .network_name
                .as_ref()
                .filter(|network_name| !network_name.is_empty())
            else {
                return Err(State {
                    phase: Phase::Error.into(),
                    reason: "Missing Astra OVN network_name".to_string(),
                    message: "create_virtual_network_attachment".to_string(),
                });
            };

            spec.attachment_type = AttachmentType::Ovn.into();
            spec.attachment_ovn = Some(AttachmentOvn {
                network_name: network_name.clone(),
            });
        }
    }

    Ok(spec)
}

// Take a diff of the Astra config vs the DOCA Weave server virtual networks and
// create new virtual networks on the server.
async fn create_weave_ew_vpc_virtual_networks(
    socket_path: &str,
    astra_config_status: &mut AstraConfigStatus,
) -> eyre::Result<()> {
    // Get list of existing VNIs from the Doca Weave server
    let list_vni_req = ListVirtualNetworksRequest { vni: None };
    let list_vni_rsp = weave_ew_vpc_list_virtual_networks(socket_path, list_vni_req).await?;

    log_virtual_networks(&list_vni_rsp.virtual_networks);

    let mut seen_vni_states: HashMap<u32, State> = list_vni_rsp
        .virtual_networks
        .iter()
        .filter_map(|virtual_network| {
            let vni = virtual_network.spec.as_ref()?.vni;
            // Preserve "Virtual Network exists but is not usable" locally when the server omits status.
            let state = virtual_network
                .status
                .as_ref()
                .and_then(|status| status.state.clone())
                .unwrap_or_else(|| State {
                    phase: Phase::Error.into(),
                    reason: "Response is missing state".to_string(),
                    message: "list_virtual_networks".to_string(),
                });
            Some((vni, state))
        })
        .collect();

    // Diff DOCA Weave server vs Astra Attachment virtual networks.
    // Create any missing virtual networks on the DOCA Weave server.
    for astra_attachment_status in &mut astra_config_status.astra_attachments_status {
        if astra_attachment_status.vni == 0 {
            tracing::trace!(
                ?astra_attachment_status,
                "Skipping virtual network sync for Astra attachment with VNI 0"
            );
            continue;
        }

        let astra_vni = astra_attachment_status.vni as u32;
        if let Some(weave_ew_vpc_state) = seen_vni_states.get(&astra_vni) {
            if weave_ew_vpc_state.phase != Phase::Ready as i32 {
                set_astra_attachment_status_with_weave_ew_vpc_not_ready(
                    astra_attachment_status,
                    weave_ew_vpc_state.clone(),
                );
            }
            continue;
        }

        let astra_subnet_ipv4 = format!(
            "{}/{}",
            astra_attachment_status.subnet_ipv4, astra_attachment_status.subnet_mask
        );

        let create_vni_req = CreateVirtualNetworkRequest {
            metadata: Some(ObjectMetadata {
                id: Some(astra_weave_ew_vpc_virtual_network_id(
                    astra_attachment_status.vni,
                )),
                creation_timestamp: Some(
                    prost_types::Timestamp::date_time_nanos(2026, 1, 1, 0, 0, 0, 0).unwrap(),
                ),
                deletion_timestamp: None,
                user_data: HashMap::new(),
            }),
            spec: Some(VirtualNetworkSpec {
                vni: astra_attachment_status.vni as u32,
                subnet_ipv4: Some(astra_subnet_ipv4.clone()),
                subnet_ipv6: None,
            }),
        };

        let create_vni_rsp = weave_ew_vpc_create_virtual_network(socket_path, create_vni_req).await;
        let weave_ew_vpc_state = match create_vni_rsp {
            Ok(create_vni_rsp) => match create_vni_rsp.virtual_network {
                Some(virtual_network) => {
                    let weave_ew_vpc_state = virtual_network
                        .status
                        .and_then(|status| status.state)
                        .unwrap_or_else(|| State {
                            phase: Phase::Error.into(),
                            reason: "Response is missing state".to_string(),
                            message: "create_virtual_network".to_string(),
                        });
                    seen_vni_states.insert(astra_vni, weave_ew_vpc_state.clone());
                    weave_ew_vpc_state
                }
                None => State {
                    phase: Phase::Error.into(),
                    reason: "Response is missing virtual network".to_string(),
                    message: "create_virtual_network".to_string(),
                },
            },
            Err(err) => State {
                phase: Phase::Error.into(),
                reason: "API failure".to_string(),
                message: format!("create_virtual_network: {err:#}"),
            },
        };

        if weave_ew_vpc_state.phase != Phase::Ready as i32 {
            set_astra_attachment_status_with_weave_ew_vpc_not_ready(
                astra_attachment_status,
                weave_ew_vpc_state,
            );
            continue;
        }

        tracing::info!(
            "Created virtual network from astra attachment status {:?}",
            astra_attachment_status
        );
    }

    Ok(())
}

async fn delete_stale_weave_ew_vpc_virtual_networks(
    socket_path: &str,
    astra_config_status: &AstraConfigStatus,
) -> eyre::Result<()> {
    let list_vni_req = ListVirtualNetworksRequest { vni: None };
    let list_vni_rsp = weave_ew_vpc_list_virtual_networks(socket_path, list_vni_req).await?;

    // Diff AstraAttachment with DOCA Weave server virtual networks.
    // Delete any extra virtual networks from the DOCA Weave server.
    for virtual_network in list_vni_rsp.virtual_networks {
        if virtual_network
            .spec
            .as_ref()
            .is_some_and(|spec| spec.vni == 0)
        {
            tracing::trace!(
                ?virtual_network,
                "Skipping virtual network with invalid VNI 0"
            );
            continue;
        }

        let vni_exists =
            astra_config_status
                .astra_attachments_status
                .iter()
                .any(|astra_attachment_status| {
                    virtual_network
                        .spec
                        .as_ref()
                        .is_some_and(|spec| spec.vni == astra_attachment_status.vni as u32)
                });

        if !vni_exists {
            let Some(delete_vni_id) = virtual_network
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.id.as_ref())
                .filter(|id| !id.is_empty())
            else {
                tracing::error!(
                    ?virtual_network,
                    "Cannot delete virtual network from DOCA Weave server because metadata id is missing or empty"
                );
                continue;
            };
            let delete_vni_req = DeleteVirtualNetworkRequest {
                id: delete_vni_id.clone(),
            };
            match weave_ew_vpc_delete_virtual_network(socket_path, delete_vni_req).await {
                Ok(_) => {
                    tracing::info!(
                        "Deleted virtual network {:?} from DOCA Weave server",
                        virtual_network
                    );
                }
                Err(err) => {
                    return Err(eyre::eyre!(
                        "failed to delete stale virtual network from DOCA Weave server: {err:#}"
                    ));
                }
            }
        }
    }

    Ok(())
}

// Take a diff of Doca Weave Server vs Astra Attachments (both ways)
// and create or delete attachments as needed. Handle special case
// where an attachment may have changed its partition aka vni.
async fn update_weave_ew_vpc_astra_attachments(
    socket_path: &str,
    astra_config_status: &mut AstraConfigStatus,
) -> eyre::Result<()> {
    // Get list of vni attachments from DOCA Weave server.
    let list_vni_attachments_req = ListVirtualNetworkAttachmentsRequest {
        vnet_id: None,
        nic_id: None,
    };
    let list_vni_attachments_rsp =
        weave_ew_vpc_list_virtual_network_attachments(socket_path, list_vni_attachments_req)
            .await?;
    log_virtual_network_attachments(&list_vni_attachments_rsp.virtual_network_attachments);
    let mut deleted_attachment_ids = HashSet::new();

    // Diff Doca Weave Server vs AstraAttachments to create new attachments.
    // Handle special case where an existing attachment has changed its
    // partition (vni) by deleting and re-creating the attachment.
    for astra_attachment_status in &mut astra_config_status.astra_attachments_status {
        // Skip any attachments where the status is not ready
        if astra_attachment_status
            .status
            .as_ref()
            .is_none_or(|status| status.phase != AstraPhase::PhaseReady as i32)
        {
            continue;
        }

        let desired_vnet_id = astra_weave_ew_vpc_virtual_network_id(astra_attachment_status.vni);
        let same_nic_attachments = list_vni_attachments_rsp
            .virtual_network_attachments
            .iter()
            .filter(|virtual_network_attachment| {
                virtual_network_attachment
                    .spec
                    .as_ref()
                    .is_some_and(|spec| {
                        spec.nic_id.as_str() == astra_attachment_status.mac_address.as_str()
                    })
            })
            .collect::<Vec<_>>();

        let mut exact_attachment = None;
        let mut conflicting_attachments = Vec::new();
        for weave_ew_vpc_attachment in same_nic_attachments {
            if weave_ew_vpc_attachment
                .spec
                .as_ref()
                .is_some_and(|spec| spec.vnet_id == desired_vnet_id)
            {
                exact_attachment = Some(weave_ew_vpc_attachment);
            } else {
                conflicting_attachments.push(weave_ew_vpc_attachment);
            }
        }

        let mut all_conflicting_attachments_deleted = true;
        for conflicting_attachment in conflicting_attachments {
            let deleted = delete_match_attachment_with_vni_changed(
                socket_path,
                Some(conflicting_attachment),
                &mut deleted_attachment_ids,
                astra_attachment_status,
            )
            .await?;
            if !deleted {
                all_conflicting_attachments_deleted = false;
            }
        }
        if !all_conflicting_attachments_deleted {
            continue;
        }

        // Skip create if we have an exact matching attachment.
        if let Some(exact_attachment) = exact_attachment {
            let weave_ew_vpc_state = exact_attachment
                .status
                .as_ref()
                .and_then(|status| status.state.clone())
                .unwrap_or_else(|| State {
                    phase: Phase::Error.into(),
                    reason: "Missing Doca Weave Server Status State".to_string(),
                    message: "list_virtual_network_attachments".to_string(),
                });
            set_astra_attachment_status_with_weave_ew_vpc_not_ready(
                astra_attachment_status,
                weave_ew_vpc_state,
            );
            continue;
        }

        // Create or recreate new attachments
        if astra_attachment_status.vni == 0 {
            tracing::trace!(
                ?astra_attachment_status,
                "Skipping virtual network attachment create for Astra attachment with VNI 0"
            );
            continue;
        }

        let weave_ew_vpc_attachment_spec =
            match astra_attachment_weave_ew_vpc_spec(astra_attachment_status) {
                Ok(weave_ew_vpc_attachment_spec) => weave_ew_vpc_attachment_spec,
                Err(weave_ew_vpc_state) => {
                    set_astra_attachment_status_with_weave_ew_vpc_not_ready(
                        &mut *astra_attachment_status,
                        weave_ew_vpc_state,
                    );
                    continue;
                }
            };

        let weave_ew_vpc_attachment_create_req = CreateVirtualNetworkAttachmentRequest {
            metadata: Some(ObjectMetadata {
                id: None,
                creation_timestamp: Some(
                    prost_types::Timestamp::date_time_nanos(2026, 1, 1, 0, 0, 0, 0).unwrap(),
                ),
                deletion_timestamp: None,
                user_data: HashMap::new(),
            }),
            spec: Some(weave_ew_vpc_attachment_spec),
        };

        let weave_ew_vpc_attachment_create_rsp = weave_ew_vpc_create_virtual_network_attachment(
            socket_path,
            weave_ew_vpc_attachment_create_req,
        )
        .await;
        let weave_ew_vpc_state = match weave_ew_vpc_attachment_create_rsp {
            Ok(weave_ew_vpc_attachment_create_rsp) => weave_ew_vpc_attachment_create_rsp
                .virtual_network_attachment
                .and_then(|virtual_network_attachment| virtual_network_attachment.status)
                .and_then(|status| status.state)
                .unwrap_or_else(|| State {
                    phase: Phase::Error.into(),
                    reason: "Missing Doca Weave Server Status State".to_string(),
                    message: "create_virtual_network_attachment".to_string(),
                }),
            Err(err) => State {
                phase: Phase::Error.into(),
                reason: "API Failed".to_string(),
                message: format!("create_virtual_network_attachment: {err:#}"),
            },
        };

        if weave_ew_vpc_state.phase != Phase::Ready as i32 {
            set_astra_attachment_status_with_weave_ew_vpc_not_ready(
                astra_attachment_status,
                weave_ew_vpc_state,
            );
            continue;
        }

        tracing::info!(
            "Created virtual network attachment for attachment status {:?}",
            astra_attachment_status
        );
    }

    // Delete any attachments that no longer exist on the DOCA Weave server.
    for virtual_network_attachment in list_vni_attachments_rsp.virtual_network_attachments {
        if virtual_network_attachment
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.id.as_ref())
            .is_some_and(|id| deleted_attachment_ids.contains(id))
        {
            continue;
        }

        let virtual_network_attachment_exists = astra_config_status
            .astra_attachments_status
            .iter()
            .any(|astra_attachment_status| {
                virtual_network_attachment
                    .spec
                    .as_ref()
                    .is_some_and(|spec| {
                        astra_attachment_status.vni != 0
                            && spec.nic_id == astra_attachment_status.mac_address.as_str()
                            && spec.vnet_id
                                == astra_weave_ew_vpc_virtual_network_id(
                                    astra_attachment_status.vni,
                                )
                    })
            });

        if !virtual_network_attachment_exists {
            let Some(del_attachment_id) = virtual_network_attachment
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.id.clone())
                .filter(|id| !id.is_empty())
            else {
                tracing::error!(
                    ?virtual_network_attachment,
                    "Cannot delete virtual network attachment from DOCA Weave server because metadata id is missing or empty"
                );
                continue;
            };

            let weave_ew_vpc_del_attachment_req = DeleteVirtualNetworkAttachmentRequest {
                id: del_attachment_id,
            };

            match weave_ew_vpc_delete_virtual_network_attachment(
                socket_path,
                weave_ew_vpc_del_attachment_req,
            )
            .await
            {
                Ok(_) => {
                    tracing::info!(
                        "Deleted virtual network attachment {:?} from DOCA Weave server",
                        virtual_network_attachment
                    );
                }
                Err(err) => {
                    return Err(eyre::eyre!(
                        "failed to delete stale virtual network attachment from DOCA Weave server: {err:#}"
                    ));
                }
            }
        }
    }

    Ok(())
}

pub async fn delete_match_attachment_with_vni_changed(
    socket_path: &str,
    match_attachment: Option<&VirtualNetworkAttachment>,
    deleted_attachment_ids: &mut HashSet<String>,
    astra_attachment_status: &mut AstraAttachmentStatus,
) -> eyre::Result<bool> {
    let Some(delete_attachment_id) = match_attachment
        .and_then(|attachment| attachment.metadata.as_ref())
        .and_then(|metadata| metadata.id.clone())
        .filter(|id| !id.is_empty())
    else {
        tracing::error!(
            ?match_attachment,
            "Cannot delete mismatched virtual network attachment from DOCA Weave server as metadata id missing or empty"
        );
        set_astra_attachment_status_with_weave_ew_vpc_not_ready(
            &mut *astra_attachment_status,
            State {
                phase: Phase::Error.into(),
                reason: "Missing Doca Weave attachment ID".to_string(),
                message: "delete_virtual_network_attachment".to_string(),
            },
        );
        return Ok(false);
    };

    let weave_ew_vpc_attachment_del_req = DeleteVirtualNetworkAttachmentRequest {
        id: delete_attachment_id.clone(),
    };
    match weave_ew_vpc_delete_virtual_network_attachment(
        socket_path,
        weave_ew_vpc_attachment_del_req,
    )
    .await
    {
        Ok(_) => {
            deleted_attachment_ids.insert(delete_attachment_id);
            tracing::info!(
                "Deleted mismatched virtual network attachment {:?} from DOCA Weave server",
                match_attachment.as_ref().unwrap()
            );
        }
        Err(err) => {
            tracing::error!(
                error = format!("{err:#}"),
                ?match_attachment,
                "Failed to delete mismatched virtual network attachment from DOCA Weave server"
            );
            set_astra_attachment_status_with_weave_ew_vpc_not_ready(
                &mut *astra_attachment_status,
                State {
                    phase: Phase::Error.into(),
                    reason: "Failed to delete mismatched Doca Weave attachment".to_string(),
                    message: format!("delete_virtual_network_attachment: {err:#}"),
                },
            );
            return Ok(false);
        }
    };
    Ok(true)
}

pub async fn update_weave_ew_vpc_astra_config(
    astra_config: Option<&AstraConfig>,
) -> eyre::Result<AstraConfigStatus> {
    update_weave_ew_vpc_astra_config_uds(WEAVE_EW_VPC_FLOW_CONTROLLER_SOCKET_PATH, astra_config)
        .await
}

async fn update_weave_ew_vpc_astra_config_uds(
    socket_path: &str,
    astra_config: Option<&AstraConfig>,
) -> eyre::Result<AstraConfigStatus> {
    let Some(astra_config) = astra_config else {
        return Ok(AstraConfigStatus {
            astra_attachments_status: Vec::new(),
        });
    };

    log_astra_config(astra_config);

    let mut astra_config_status = build_astra_config_status(astra_config)?;

    create_weave_ew_vpc_virtual_networks(socket_path, &mut astra_config_status).await?;

    update_weave_ew_vpc_astra_attachments(socket_path, &mut astra_config_status).await?;

    delete_stale_weave_ew_vpc_virtual_networks(socket_path, &astra_config_status).await?;

    Ok(astra_config_status)
}

fn log_astra_config(astra_config: &AstraConfig) {
    tracing::info!(
        attachment_count = astra_config.astra_attachments.len(),
        "Input Astra config"
    );
    for astra_attachment in &astra_config.astra_attachments {
        tracing::info!(?astra_attachment, "Input Astra config entry");
    }
}

fn log_virtual_networks(virtual_networks: &[crate::weave_ew_vpc_client::proto::VirtualNetwork]) {
    tracing::info!(
        virtual_network_count = virtual_networks.len(),
        "List VNI response"
    );
    for virtual_network in virtual_networks {
        tracing::info!(?virtual_network, "List VNI response entry");
    }
}

fn log_virtual_network_attachments(virtual_network_attachments: &[VirtualNetworkAttachment]) {
    tracing::info!(
        virtual_network_attachment_count = virtual_network_attachments.len(),
        "List VNI attachment response"
    );
    for virtual_network_attachment in virtual_network_attachments {
        tracing::info!(
            ?virtual_network_attachment,
            "List VNI attachment response entry"
        );
    }
}

fn build_astra_config_status(astra_config: &AstraConfig) -> eyre::Result<AstraConfigStatus> {
    // Pre-build astra_config_status as a vector of AstraAttachmentStatus
    // that contains the Astra Attachment info and status is set to
    // Phase::Ready. We will walk this vector and update the status
    // if there is an API failure. We use this vector to avoid
    // repeatedly walking an entry that has encountered an error.
    let mut astra_config_status = AstraConfigStatus {
        astra_attachments_status: Vec::new(),
    };

    for astra_attachment in &astra_config.astra_attachments {
        let astra_attachment_status = AstraAttachmentStatus {
            mac_address: astra_attachment.mac_address.clone(),
            vni: i32::try_from(astra_attachment.vni)
                .wrap_err_with(|| format!("VNI {} does not fit in i32", astra_attachment.vni))?,
            subnet_ipv4: astra_attachment.subnet_ipv4.clone(),
            subnet_mask: astra_attachment.subnet_mask,
            attachment_type: astra_attachment.attachment_type,
            virtual_function_id: astra_attachment.virtual_function_id,
            network_name: astra_attachment.network_name.clone(),
            revision: astra_attachment.revision.clone(),
            status: Some(AstraStatus {
                phase: AstraPhase::PhaseReady.into(),
                reason: String::new(),
                message: String::new(),
            }),
        };
        astra_config_status
            .astra_attachments_status
            .push(astra_attachment_status);
    }

    Ok(astra_config_status)
}

pub fn set_astra_attachment_status_with_weave_ew_vpc_not_ready(
    astra_attachment_status: &mut AstraAttachmentStatus,
    weave_ew_vpc_state: State,
) {
    let astra_status_phase =
        match Phase::try_from(weave_ew_vpc_state.phase).unwrap_or(Phase::Unspecified) {
            Phase::Ready => AstraPhase::PhaseReady,
            Phase::Error => AstraPhase::PhaseError,
            Phase::Pending => AstraPhase::PhasePending,
            Phase::Deleting => AstraPhase::PhaseDeleting,
            _ => AstraPhase::PhaseUnspecified,
        };

    astra_attachment_status.status = Some(AstraStatus {
        phase: astra_status_phase.into(),
        reason: weave_ew_vpc_state.reason,
        message: weave_ew_vpc_state.message,
    });
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use ::rpc::forge as rpc;
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::{Request, Response, Status};

    use super::*;
    use crate::weave_ew_vpc_client::proto::network_isolation_service_server::{
        NetworkIsolationService, NetworkIsolationServiceServer,
    };
    use crate::weave_ew_vpc_client::proto::state::Phase as WeaveEwVpcPhase;
    use crate::weave_ew_vpc_client::proto::{self, State};

    #[ctor::ctor(unsafe)]
    fn setup() {
        carbide_host_support::init_logging("nico-dpu-agent").unwrap();
    }

    #[derive(Default)]
    struct RecordedWeaveEwVpcCalls {
        list_virtual_networks: usize,
        create_virtual_networks: Vec<proto::CreateVirtualNetworkRequest>,
        delete_virtual_networks: Vec<proto::DeleteVirtualNetworkRequest>,
        list_virtual_network_attachments: usize,
        create_virtual_network_attachments: Vec<proto::CreateVirtualNetworkAttachmentRequest>,
        delete_virtual_network_attachments: Vec<proto::DeleteVirtualNetworkAttachmentRequest>,
    }

    struct RecordedWeaveEwVpcState {
        virtual_networks: Vec<proto::VirtualNetwork>,
        virtual_network_attachments: Vec<proto::VirtualNetworkAttachment>,
    }

    struct RecordingNetworkIsolationService {
        state: Arc<Mutex<RecordedWeaveEwVpcState>>,
        calls: Arc<Mutex<RecordedWeaveEwVpcCalls>>,
        create_virtual_network_phase: WeaveEwVpcPhase,
    }

    #[tonic::async_trait]
    impl NetworkIsolationService for RecordingNetworkIsolationService {
        async fn create_virtual_network(
            &self,
            request: Request<proto::CreateVirtualNetworkRequest>,
        ) -> Result<Response<proto::CreateVirtualNetworkResponse>, Status> {
            let request = request.into_inner();
            self.calls
                .lock()
                .await
                .create_virtual_networks
                .push(request.clone());

            let mut metadata = request.metadata.unwrap_or_default();
            if metadata.id.is_none() {
                let vni = request.spec.as_ref().map_or(0, |spec| spec.vni);
                metadata.id = Some(astra_weave_ew_vpc_virtual_network_id(vni as i32));
            }

            let virtual_network = proto::VirtualNetwork {
                metadata: Some(metadata),
                spec: request.spec,
                status: Some(proto::VirtualNetworkStatus {
                    state: Some(State {
                        phase: self.create_virtual_network_phase.into(),
                        reason: String::new(),
                        message: String::new(),
                    }),
                }),
            };
            self.state
                .lock()
                .await
                .virtual_networks
                .push(virtual_network.clone());

            Ok(Response::new(proto::CreateVirtualNetworkResponse {
                virtual_network: Some(virtual_network),
            }))
        }

        async fn delete_virtual_network(
            &self,
            request: Request<proto::DeleteVirtualNetworkRequest>,
        ) -> Result<Response<proto::DeleteVirtualNetworkResponse>, Status> {
            let request = request.into_inner();
            self.calls
                .lock()
                .await
                .delete_virtual_networks
                .push(request.clone());
            self.state
                .lock()
                .await
                .virtual_networks
                .retain(|virtual_network| {
                    virtual_network
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.id.as_deref())
                        != Some(request.id.as_str())
                });

            Ok(Response::new(proto::DeleteVirtualNetworkResponse {}))
        }

        async fn get_virtual_network(
            &self,
            _request: Request<proto::GetVirtualNetworkRequest>,
        ) -> Result<Response<proto::GetVirtualNetworkResponse>, Status> {
            Err(Status::unimplemented("not used by astra config tests"))
        }

        async fn list_virtual_networks(
            &self,
            _request: Request<proto::ListVirtualNetworksRequest>,
        ) -> Result<Response<proto::ListVirtualNetworksResponse>, Status> {
            self.calls.lock().await.list_virtual_networks += 1;

            Ok(Response::new(proto::ListVirtualNetworksResponse {
                virtual_networks: self.state.lock().await.virtual_networks.clone(),
            }))
        }

        async fn create_virtual_network_attachment(
            &self,
            request: Request<proto::CreateVirtualNetworkAttachmentRequest>,
        ) -> Result<Response<proto::CreateVirtualNetworkAttachmentResponse>, Status> {
            let request = request.into_inner();
            self.calls
                .lock()
                .await
                .create_virtual_network_attachments
                .push(request.clone());

            let mut metadata = request.metadata.unwrap_or_default();
            if metadata.id.is_none() {
                let id = request.spec.as_ref().map_or_else(
                    || "attachment-missing-spec".to_string(),
                    |spec| format!("attachment-{}-{}", spec.nic_id, spec.vnet_id),
                );
                metadata.id = Some(id);
            }

            let virtual_network_attachment = proto::VirtualNetworkAttachment {
                metadata: Some(metadata),
                spec: request.spec,
                status: Some(proto::VirtualNetworkAttachmentStatus {
                    state: Some(State {
                        phase: WeaveEwVpcPhase::Ready.into(),
                        reason: String::new(),
                        message: String::new(),
                    }),
                    host_ipv4: None,
                    host_ipv6: None,
                }),
            };
            self.state
                .lock()
                .await
                .virtual_network_attachments
                .push(virtual_network_attachment.clone());

            Ok(Response::new(
                proto::CreateVirtualNetworkAttachmentResponse {
                    virtual_network_attachment: Some(virtual_network_attachment),
                },
            ))
        }

        async fn delete_virtual_network_attachment(
            &self,
            request: Request<proto::DeleteVirtualNetworkAttachmentRequest>,
        ) -> Result<Response<proto::DeleteVirtualNetworkAttachmentResponse>, Status> {
            let request = request.into_inner();
            self.calls
                .lock()
                .await
                .delete_virtual_network_attachments
                .push(request.clone());
            self.state.lock().await.virtual_network_attachments.retain(
                |virtual_network_attachment| {
                    virtual_network_attachment
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.id.as_deref())
                        != Some(request.id.as_str())
                },
            );

            Ok(Response::new(
                proto::DeleteVirtualNetworkAttachmentResponse {},
            ))
        }

        async fn get_virtual_network_attachment(
            &self,
            _request: Request<proto::GetVirtualNetworkAttachmentRequest>,
        ) -> Result<Response<proto::GetVirtualNetworkAttachmentResponse>, Status> {
            Err(Status::unimplemented("not used by astra config tests"))
        }

        async fn list_virtual_network_attachments(
            &self,
            _request: Request<proto::ListVirtualNetworkAttachmentsRequest>,
        ) -> Result<Response<proto::ListVirtualNetworkAttachmentsResponse>, Status> {
            self.calls.lock().await.list_virtual_network_attachments += 1;

            Ok(Response::new(
                proto::ListVirtualNetworkAttachmentsResponse {
                    virtual_network_attachments: self
                        .state
                        .lock()
                        .await
                        .virtual_network_attachments
                        .clone(),
                },
            ))
        }
    }

    async fn start_recording_weave_ew_vpc_mock_server(
        virtual_networks: Vec<proto::VirtualNetwork>,
        virtual_network_attachments: Vec<proto::VirtualNetworkAttachment>,
    ) -> (PathBuf, Arc<Mutex<RecordedWeaveEwVpcCalls>>) {
        start_recording_weave_ew_vpc_mock_server_with_create_phase(
            virtual_networks,
            virtual_network_attachments,
            WeaveEwVpcPhase::Ready,
        )
        .await
    }

    async fn start_recording_weave_ew_vpc_mock_server_with_create_phase(
        virtual_networks: Vec<proto::VirtualNetwork>,
        virtual_network_attachments: Vec<proto::VirtualNetworkAttachment>,
        create_virtual_network_phase: WeaveEwVpcPhase,
    ) -> (PathBuf, Arc<Mutex<RecordedWeaveEwVpcCalls>>) {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");
        let _keep = dir.keep();
        let calls = Arc::new(Mutex::new(RecordedWeaveEwVpcCalls::default()));
        let state = Arc::new(Mutex::new(RecordedWeaveEwVpcState {
            virtual_networks,
            virtual_network_attachments,
        }));
        let service = RecordingNetworkIsolationService {
            state,
            calls: calls.clone(),
            create_virtual_network_phase,
        };
        let path_clone = socket_path.clone();
        tokio::spawn(async move {
            let listener = UnixListener::bind(path_clone).unwrap();
            let stream = UnixListenerStream::new(listener);
            tonic::transport::Server::builder()
                .add_service(NetworkIsolationServiceServer::new(service))
                .serve_with_incoming(stream)
                .await
                .unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (socket_path, calls)
    }

    fn astra_attachment(mac_address: &str, vni: u32) -> rpc::AstraAttachment {
        rpc::AstraAttachment {
            mac_address: mac_address.to_string(),
            vni,
            subnet_ipv4: "192.0.2.0".to_string(),
            subnet_mask: 24,
            attachment_type: Some(rpc::SpxAttachmentType::Physical as i32),
            virtual_function_id: Some(7),
            network_name: Some("test-network".to_string()),
            revision: "test-revision".to_string(),
        }
    }

    fn weave_ew_vpc_virtual_network(id: &str, vni: u32) -> proto::VirtualNetwork {
        weave_ew_vpc_virtual_network_with_phase(id, vni, WeaveEwVpcPhase::Ready)
    }

    fn weave_ew_vpc_virtual_network_with_phase(
        id: &str,
        vni: u32,
        phase: WeaveEwVpcPhase,
    ) -> proto::VirtualNetwork {
        proto::VirtualNetwork {
            metadata: Some(proto::ObjectMetadata {
                id: Some(id.to_string()),
                creation_timestamp: Some(
                    prost_types::Timestamp::date_time_nanos(2026, 1, 1, 0, 0, 0, 0).unwrap(),
                ),
                ..Default::default()
            }),
            spec: Some(proto::VirtualNetworkSpec {
                vni,
                subnet_ipv4: Some("192.0.2.0/24".to_string()),
                subnet_ipv6: None,
            }),
            status: Some(proto::VirtualNetworkStatus {
                state: Some(State {
                    phase: phase.into(),
                    reason: String::new(),
                    message: String::new(),
                }),
            }),
        }
    }

    fn weave_ew_vpc_virtual_network_attachment(
        id: &str,
        nic_id: &str,
        vnet_id: &str,
    ) -> proto::VirtualNetworkAttachment {
        proto::VirtualNetworkAttachment {
            metadata: Some(proto::ObjectMetadata {
                id: Some(id.to_string()),
                creation_timestamp: Some(
                    prost_types::Timestamp::date_time_nanos(2026, 1, 1, 0, 0, 0, 0).unwrap(),
                ),
                ..Default::default()
            }),
            spec: Some(proto::VirtualNetworkAttachmentSpec {
                vnet_id: vnet_id.to_string(),
                nic_id: nic_id.to_string(),
                attachment_type: proto::AttachmentType::Pf.into(),
                attachment_pf: None,
                attachment_vf: None,
                attachment_ovn: None,
            }),
            status: Some(proto::VirtualNetworkAttachmentStatus {
                state: Some(State {
                    phase: WeaveEwVpcPhase::Ready.into(),
                    reason: String::new(),
                    message: String::new(),
                }),
                host_ipv4: None,
                host_ipv6: None,
            }),
        }
    }

    #[tokio::test]
    async fn test_update_weave_ew_vpc_server_astra_config_none_returns_empty_status()
    -> eyre::Result<()> {
        let status = update_weave_ew_vpc_astra_config(None).await?;

        assert!(status.astra_attachments_status.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_update_weave_ew_vpc_server_astra_config_adds_missing_vni_and_attachment()
    -> eyre::Result<()> {
        let (socket_path, calls) =
            start_recording_weave_ew_vpc_mock_server(Vec::new(), Vec::new()).await;
        let socket_path = socket_path.to_str().unwrap();
        let astra_config = rpc::AstraConfig {
            astra_attachments: vec![astra_attachment("02:aa:bb:cc:dd:ee", 100)],
        };

        let status = update_weave_ew_vpc_astra_config_uds(socket_path, Some(&astra_config)).await?;
        let calls = calls.lock().await;

        assert_eq!(status.astra_attachments_status.len(), 1);
        assert_eq!(calls.list_virtual_networks, 2);
        assert_eq!(calls.list_virtual_network_attachments, 1);
        assert_eq!(calls.create_virtual_networks.len(), 1);
        assert_eq!(
            calls.create_virtual_networks[0].spec.as_ref().unwrap().vni,
            100
        );
        assert_eq!(calls.create_virtual_network_attachments.len(), 1);
        assert_eq!(
            calls.create_virtual_network_attachments[0]
                .spec
                .as_ref()
                .unwrap()
                .vnet_id,
            "astra-weave-vni-100"
        );
        assert!(
            calls.create_virtual_network_attachments[0]
                .spec
                .as_ref()
                .unwrap()
                .attachment_pf
                .is_some()
        );
        assert!(calls.delete_virtual_networks.is_empty());
        assert!(calls.delete_virtual_network_attachments.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_update_weave_ew_vpc_server_astra_config_creates_shared_vni_once()
    -> eyre::Result<()> {
        let (socket_path, calls) =
            start_recording_weave_ew_vpc_mock_server(Vec::new(), Vec::new()).await;
        let socket_path = socket_path.to_str().unwrap();
        let astra_config = rpc::AstraConfig {
            astra_attachments: vec![
                astra_attachment("02:aa:bb:cc:dd:ee", 100),
                astra_attachment("02:aa:bb:cc:dd:ff", 100),
            ],
        };

        let status = update_weave_ew_vpc_astra_config_uds(socket_path, Some(&astra_config)).await?;
        let calls = calls.lock().await;

        assert_eq!(status.astra_attachments_status.len(), 2);
        assert_eq!(calls.create_virtual_networks.len(), 1);
        assert_eq!(
            calls.create_virtual_networks[0].spec.as_ref().unwrap().vni,
            100
        );
        assert_eq!(calls.create_virtual_network_attachments.len(), 2);
        assert!(
            calls
                .create_virtual_network_attachments
                .iter()
                .all(|request| request.spec.as_ref().unwrap().vnet_id == "astra-weave-vni-100")
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_update_weave_ew_vpc_server_astra_config_marks_pending_vni_seen()
    -> eyre::Result<()> {
        let (socket_path, calls) = start_recording_weave_ew_vpc_mock_server_with_create_phase(
            Vec::new(),
            Vec::new(),
            WeaveEwVpcPhase::Pending,
        )
        .await;
        let socket_path = socket_path.to_str().unwrap();
        let astra_config = rpc::AstraConfig {
            astra_attachments: vec![
                astra_attachment("02:aa:bb:cc:dd:ee", 100),
                astra_attachment("02:aa:bb:cc:dd:ff", 100),
            ],
        };

        let status = update_weave_ew_vpc_astra_config_uds(socket_path, Some(&astra_config)).await?;
        let calls = calls.lock().await;

        assert_eq!(status.astra_attachments_status.len(), 2);
        assert_eq!(
            status.astra_attachments_status[0]
                .status
                .as_ref()
                .unwrap()
                .phase,
            rpc::AstraPhase::PhasePending as i32
        );
        assert_eq!(calls.create_virtual_networks.len(), 1);
        assert_eq!(
            calls.create_virtual_networks[0].spec.as_ref().unwrap().vni,
            100
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_update_weave_ew_vpc_server_astra_config_marks_existing_pending_vni_not_ready()
    -> eyre::Result<()> {
        let (socket_path, calls) = start_recording_weave_ew_vpc_mock_server(
            vec![weave_ew_vpc_virtual_network_with_phase(
                "pending-vni",
                100,
                WeaveEwVpcPhase::Pending,
            )],
            Vec::new(),
        )
        .await;
        let socket_path = socket_path.to_str().unwrap();
        let astra_config = rpc::AstraConfig {
            astra_attachments: vec![
                astra_attachment("02:aa:bb:cc:dd:ee", 100),
                astra_attachment("02:aa:bb:cc:dd:ff", 100),
            ],
        };

        let status = update_weave_ew_vpc_astra_config_uds(socket_path, Some(&astra_config)).await?;
        let calls = calls.lock().await;

        assert_eq!(status.astra_attachments_status.len(), 2);
        assert!(status.astra_attachments_status.iter().all(|attachment| {
            attachment
                .status
                .as_ref()
                .is_some_and(|status| status.phase == rpc::AstraPhase::PhasePending as i32)
        }));
        assert!(calls.create_virtual_networks.is_empty());
        assert!(calls.create_virtual_network_attachments.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_update_weave_ew_vpc_server_astra_config_deletes_stale_vni_and_attachment()
    -> eyre::Result<()> {
        let (socket_path, calls) = start_recording_weave_ew_vpc_mock_server(
            vec![weave_ew_vpc_virtual_network("stale-vni", 300)],
            vec![weave_ew_vpc_virtual_network_attachment(
                "stale-attachment",
                "02:aa:bb:cc:dd:ee",
                "300",
            )],
        )
        .await;
        let socket_path = socket_path.to_str().unwrap();
        let astra_config = rpc::AstraConfig {
            astra_attachments: Vec::new(),
        };

        let status = update_weave_ew_vpc_astra_config_uds(socket_path, Some(&astra_config)).await?;
        let calls = calls.lock().await;

        assert!(status.astra_attachments_status.is_empty());
        assert_eq!(calls.list_virtual_networks, 2);
        assert_eq!(calls.list_virtual_network_attachments, 1);
        assert!(calls.create_virtual_networks.is_empty());
        assert!(calls.create_virtual_network_attachments.is_empty());
        assert_eq!(calls.delete_virtual_networks.len(), 1);
        assert_eq!(calls.delete_virtual_networks[0].id, "stale-vni");
        assert_eq!(calls.delete_virtual_network_attachments.len(), 1);
        assert_eq!(
            calls.delete_virtual_network_attachments[0].id,
            "stale-attachment"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_update_weave_ew_vpc_server_astra_config_moves_attachment_to_new_vni()
    -> eyre::Result<()> {
        let (socket_path, calls) = start_recording_weave_ew_vpc_mock_server(
            vec![
                weave_ew_vpc_virtual_network("old-vni", 100),
                weave_ew_vpc_virtual_network("new-vni", 200),
            ],
            vec![weave_ew_vpc_virtual_network_attachment(
                "old-attachment",
                "02:aa:bb:cc:dd:ee",
                "astra-weave-vni-100",
            )],
        )
        .await;
        let socket_path = socket_path.to_str().unwrap();
        let astra_config = rpc::AstraConfig {
            astra_attachments: vec![astra_attachment("02:aa:bb:cc:dd:ee", 200)],
        };

        let status = update_weave_ew_vpc_astra_config_uds(socket_path, Some(&astra_config)).await?;
        let calls = calls.lock().await;

        assert_eq!(status.astra_attachments_status.len(), 1);
        assert!(calls.create_virtual_networks.is_empty());
        assert_eq!(calls.delete_virtual_networks.len(), 1);
        assert_eq!(calls.delete_virtual_networks[0].id, "old-vni");
        assert_eq!(calls.delete_virtual_network_attachments.len(), 1);
        assert_eq!(
            calls.delete_virtual_network_attachments[0].id,
            "old-attachment"
        );
        assert_eq!(calls.create_virtual_network_attachments.len(), 1);
        let create_attachment_spec = calls.create_virtual_network_attachments[0]
            .spec
            .as_ref()
            .unwrap();
        assert_eq!(create_attachment_spec.nic_id, "02:aa:bb:cc:dd:ee");
        assert_eq!(create_attachment_spec.vnet_id, "astra-weave-vni-200");
        assert!(create_attachment_spec.attachment_pf.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_update_weave_ew_vpc_server_astra_config_keeps_matching_vni_and_attachment()
    -> eyre::Result<()> {
        let (socket_path, calls) = start_recording_weave_ew_vpc_mock_server(
            vec![weave_ew_vpc_virtual_network("matching-vni", 100)],
            vec![weave_ew_vpc_virtual_network_attachment(
                "matching-attachment",
                "02:aa:bb:cc:dd:ee",
                "astra-weave-vni-100",
            )],
        )
        .await;
        let socket_path = socket_path.to_str().unwrap();
        let astra_config = rpc::AstraConfig {
            astra_attachments: vec![astra_attachment("02:aa:bb:cc:dd:ee", 100)],
        };

        let status = update_weave_ew_vpc_astra_config_uds(socket_path, Some(&astra_config)).await?;
        let calls = calls.lock().await;

        assert_eq!(status.astra_attachments_status.len(), 1);
        assert!(
            status
                .astra_attachments_status
                .iter()
                .all(|attachment_status| {
                    attachment_status
                        .status
                        .as_ref()
                        .is_some_and(|status| status.phase == rpc::AstraPhase::PhaseReady as i32)
                }),
            "matching Weave EW VPC inventory should keep Astra attachment statuses ready"
        );
        assert_eq!(calls.list_virtual_networks, 2);
        assert_eq!(calls.list_virtual_network_attachments, 1);
        assert!(calls.create_virtual_networks.is_empty());
        assert!(calls.delete_virtual_networks.is_empty());
        assert!(calls.create_virtual_network_attachments.is_empty());
        assert!(calls.delete_virtual_network_attachments.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_update_weave_ew_vpc_server_astra_config_skips_vni_zero_sentinel()
    -> eyre::Result<()> {
        let (socket_path, calls) = start_recording_weave_ew_vpc_mock_server(
            vec![weave_ew_vpc_virtual_network("invalid-vni-zero", 0)],
            vec![weave_ew_vpc_virtual_network_attachment(
                "stale-attachment-for-detached-mac",
                "02:aa:bb:cc:dd:ee",
                "astra-weave-vni-100",
            )],
        )
        .await;
        let socket_path = socket_path.to_str().unwrap();
        let astra_config = rpc::AstraConfig {
            astra_attachments: vec![astra_attachment("02:aa:bb:cc:dd:ee", 0)],
        };

        let status = update_weave_ew_vpc_astra_config_uds(socket_path, Some(&astra_config)).await?;
        let calls = calls.lock().await;

        assert_eq!(status.astra_attachments_status.len(), 1);
        assert_eq!(status.astra_attachments_status[0].vni, 0);
        assert_eq!(calls.list_virtual_networks, 2);
        assert_eq!(calls.list_virtual_network_attachments, 1);
        assert!(calls.create_virtual_networks.is_empty());
        assert!(calls.delete_virtual_networks.is_empty());
        assert!(calls.create_virtual_network_attachments.is_empty());
        assert_eq!(calls.delete_virtual_network_attachments.len(), 1);
        assert_eq!(
            calls.delete_virtual_network_attachments[0].id,
            "stale-attachment-for-detached-mac"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_update_weave_ew_vpc_server_astra_config_processes_full_config_sequence()
    -> eyre::Result<()> {
        let (socket_path, calls) =
            start_recording_weave_ew_vpc_mock_server(Vec::new(), Vec::new()).await;
        let socket_path = socket_path.to_str().unwrap();

        let config = |attachments: Vec<(&str, u32)>| rpc::AstraConfig {
            astra_attachments: attachments
                .into_iter()
                .map(|(mac_address, vni)| astra_attachment(mac_address, vni))
                .collect(),
        };

        let run_update = |astra_config: rpc::AstraConfig| async move {
            update_weave_ew_vpc_astra_config_uds(socket_path, Some(&astra_config)).await
        };

        run_update(config(vec![("aa:bb:cc:dd:ee:10", 100)])).await?;
        {
            let mut calls = calls.lock().await;
            assert_eq!(calls.create_virtual_networks.len(), 1);
            assert_eq!(
                calls.create_virtual_networks[0].spec.as_ref().unwrap().vni,
                100
            );
            assert_eq!(calls.create_virtual_network_attachments.len(), 1);
            assert_eq!(
                calls.create_virtual_network_attachments[0]
                    .spec
                    .as_ref()
                    .unwrap()
                    .nic_id,
                "aa:bb:cc:dd:ee:10"
            );
            assert!(calls.delete_virtual_networks.is_empty());
            assert!(calls.delete_virtual_network_attachments.is_empty());
            *calls = RecordedWeaveEwVpcCalls::default();
        }

        run_update(config(vec![
            ("aa:bb:cc:dd:ee:10", 100),
            ("aa:bb:cc:dd:ee:20", 200),
        ]))
        .await?;
        {
            let mut calls = calls.lock().await;
            assert_eq!(calls.create_virtual_networks.len(), 1);
            assert_eq!(
                calls.create_virtual_networks[0].spec.as_ref().unwrap().vni,
                200
            );
            assert_eq!(calls.create_virtual_network_attachments.len(), 1);
            assert_eq!(
                calls.create_virtual_network_attachments[0]
                    .spec
                    .as_ref()
                    .unwrap()
                    .nic_id,
                "aa:bb:cc:dd:ee:20"
            );
            assert!(calls.delete_virtual_networks.is_empty());
            assert!(calls.delete_virtual_network_attachments.is_empty());
            *calls = RecordedWeaveEwVpcCalls::default();
        }

        run_update(config(vec![
            ("aa:bb:cc:dd:ee:10", 100),
            ("aa:bb:cc:dd:ee:20", 200),
            ("as:bb:cc:dd:ee:30", 300),
        ]))
        .await?;
        {
            let mut calls = calls.lock().await;
            assert_eq!(calls.create_virtual_networks.len(), 1);
            assert_eq!(
                calls.create_virtual_networks[0].spec.as_ref().unwrap().vni,
                300
            );
            assert_eq!(calls.create_virtual_network_attachments.len(), 1);
            assert_eq!(
                calls.create_virtual_network_attachments[0]
                    .spec
                    .as_ref()
                    .unwrap()
                    .nic_id,
                "as:bb:cc:dd:ee:30"
            );
            assert!(calls.delete_virtual_networks.is_empty());
            assert!(calls.delete_virtual_network_attachments.is_empty());
            *calls = RecordedWeaveEwVpcCalls::default();
        }

        run_update(config(vec![
            ("aa:bb:cc:dd:ee:10", 100),
            ("aa:bb:cc:dd:ee:20", 400),
            ("as:bb:cc:dd:ee:30", 300),
        ]))
        .await?;
        {
            let mut calls = calls.lock().await;
            assert_eq!(calls.create_virtual_networks.len(), 1);
            assert_eq!(
                calls.create_virtual_networks[0].spec.as_ref().unwrap().vni,
                400
            );
            assert_eq!(calls.delete_virtual_networks.len(), 1);
            assert_eq!(calls.delete_virtual_networks[0].id, "astra-weave-vni-200");
            assert_eq!(calls.delete_virtual_network_attachments.len(), 1);
            assert!(
                calls.delete_virtual_network_attachments[0]
                    .id
                    .contains("aa:bb:cc:dd:ee:20")
            );
            assert_eq!(calls.create_virtual_network_attachments.len(), 1);
            let moved_attachment = calls.create_virtual_network_attachments[0]
                .spec
                .as_ref()
                .unwrap();
            assert_eq!(moved_attachment.nic_id, "aa:bb:cc:dd:ee:20");
            assert_eq!(moved_attachment.vnet_id, "astra-weave-vni-400");
            assert!(moved_attachment.attachment_pf.is_some());
            *calls = RecordedWeaveEwVpcCalls::default();
        }

        run_update(config(vec![
            ("aa:bb:cc:dd:ee:20", 400),
            ("as:bb:cc:dd:ee:30", 300),
        ]))
        .await?;
        {
            let calls = calls.lock().await;
            assert!(calls.create_virtual_networks.is_empty());
            assert!(calls.create_virtual_network_attachments.is_empty());
            assert_eq!(calls.delete_virtual_networks.len(), 1);
            assert_eq!(calls.delete_virtual_networks[0].id, "astra-weave-vni-100");
            assert_eq!(calls.delete_virtual_network_attachments.len(), 1);
            assert!(
                calls.delete_virtual_network_attachments[0]
                    .id
                    .contains("aa:bb:cc:dd:ee:10")
            );
        }

        Ok(())
    }

    #[test]
    fn test_build_astra_config_status_copies_attachments_and_sets_ready() -> eyre::Result<()> {
        let astra_config = rpc::AstraConfig {
            astra_attachments: vec![
                astra_attachment("00:11:22:33:44:55", 100),
                astra_attachment("00:11:22:33:44:66", 200),
            ],
        };

        let status = build_astra_config_status(&astra_config)?;

        assert_eq!(status.astra_attachments_status.len(), 2);

        let first_status = &status.astra_attachments_status[0];
        assert_eq!(first_status.mac_address, "00:11:22:33:44:55");
        assert_eq!(first_status.vni, 100);
        assert_eq!(first_status.subnet_ipv4, "192.0.2.0");
        assert_eq!(first_status.subnet_mask, 24);
        assert_eq!(
            first_status.attachment_type,
            Some(rpc::SpxAttachmentType::Physical as i32)
        );
        assert_eq!(first_status.virtual_function_id, Some(7));
        assert_eq!(first_status.network_name.as_deref(), Some("test-network"));
        assert_eq!(first_status.revision, "test-revision");

        let first_phase = first_status.status.as_ref().map(|status| status.phase);
        assert_eq!(first_phase, Some(rpc::AstraPhase::PhaseReady as i32));

        Ok(())
    }

    #[test]
    fn test_build_astra_config_status_rejects_vni_that_does_not_fit_i32() {
        let astra_config = rpc::AstraConfig {
            astra_attachments: vec![astra_attachment("00:11:22:33:44:55", i32::MAX as u32 + 1)],
        };

        let err = build_astra_config_status(&astra_config).unwrap_err();

        assert!(
            err.to_string().contains("does not fit in i32"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_update_astra_attachment_status_maps_vpc_phase_to_astra_phase() {
        let cases = [
            (WeaveEwVpcPhase::Ready, rpc::AstraPhase::PhaseReady),
            (WeaveEwVpcPhase::Error, rpc::AstraPhase::PhaseError),
            (WeaveEwVpcPhase::Pending, rpc::AstraPhase::PhasePending),
            (WeaveEwVpcPhase::Deleting, rpc::AstraPhase::PhaseDeleting),
            (
                WeaveEwVpcPhase::Unspecified,
                rpc::AstraPhase::PhaseUnspecified,
            ),
        ];

        for (vpc_phase, expected_astra_phase) in cases {
            let mut attachment_status = build_astra_config_status(&rpc::AstraConfig {
                astra_attachments: vec![astra_attachment("00:11:22:33:44:55", 100)],
            })
            .unwrap()
            .astra_attachments_status
            .remove(0);

            set_astra_attachment_status_with_weave_ew_vpc_not_ready(
                &mut attachment_status,
                State {
                    phase: vpc_phase as i32,
                    reason: "weave-ew-vpc-reason".to_string(),
                    message: "weave-ew-vpc-message".to_string(),
                },
            );

            let status = attachment_status.status.unwrap();
            assert_eq!(status.phase, expected_astra_phase as i32);
            assert_eq!(status.reason, "weave-ew-vpc-reason");
            assert_eq!(status.message, "weave-ew-vpc-message");
        }
    }
}
