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
use std::fmt::Debug;
use std::sync::Arc;

use ::rpc::Timestamp;
use carbide_uuid::vpc::VpcId;

use crate::config::MachineATronContext;
use crate::tui::{UiUpdate, VpcDetails};

#[derive(Debug, Clone)]
pub struct Vpc {
    pub vpc_id: VpcId,
    pub app_context: Arc<MachineATronContext>,

    pub vpc_name: String,

    pub logs: Vec<String>,

    _created: Option<Timestamp>,
}

impl Vpc {
    pub async fn new(
        app_context: Arc<MachineATronContext>,
        ui_event_tx: Option<tokio::sync::mpsc::Sender<UiUpdate>>,
    ) -> Self {
        // TODO: Add error handling when vpc creation fails.
        let vpc = app_context.api_client().create_vpc().await.unwrap();

        let new_vpc = Vpc {
            vpc_id: vpc.id.expect("VPC must have an ID."),
            app_context,
            vpc_name: vpc.name,
            logs: Vec::default(),
            _created: vpc.created,
        };

        let details = VpcDetails::from(&new_vpc);
        if let Some(ui_event_tx) = ui_event_tx.as_ref() {
            _ = ui_event_tx
                .send(UiUpdate::Vpc(details))
                .await
                .inspect_err(|e| tracing::warn!("Error sending TUI event: {}", e));
        }

        new_vpc
    }
}
