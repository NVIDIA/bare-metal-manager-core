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
use std::fmt::Debug;
use std::sync::Arc;

use ::rpc::Timestamp;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use tonic::Status;

use crate::config::MachineATronContext;
use crate::tui::{SubnetDetails, UiUpdate};

#[derive(Debug, Clone)]
pub struct Subnet {
    pub segment_id: NetworkSegmentId,

    pub vpc_id: VpcId,
    pub prefixes: Vec<String>,
    pub logs: Vec<String>,

    _created: Option<Timestamp>,
}

impl Subnet {
    pub async fn new(
        app_context: Arc<MachineATronContext>,
        ui_event_tx: Option<tokio::sync::mpsc::Sender<UiUpdate>>,
        vpc_name: &String,
    ) -> Result<Subnet, Status> {
        let network_segment = app_context
            .api_client()
            .create_network_segment(vpc_name)
            .await
            .map_err(|e| {
                tracing::error!("Error creating network segment: {}", e);
                Status::internal("Failed to create network segment.")
            })?;

        let new_subnet = Subnet {
            segment_id: network_segment.id.expect("Segment must have an ID."),
            vpc_id: network_segment.vpc_id.expect("Segment must have a VPC_ID."),
            prefixes: network_segment
                .prefixes
                .iter()
                .map(|s| s.prefix.clone())
                .collect(),
            logs: Vec::default(),
            _created: network_segment.created,
        };

        let details = SubnetDetails::from(&new_subnet);
        if let Some(ui_event_tx) = ui_event_tx.as_ref() {
            _ = ui_event_tx
                .send(UiUpdate::Subnet(details))
                .await
                .inspect_err(|e| tracing::warn!("Error sending TUI event: {}", e));
        }

        Ok(new_subnet)
    }
}
