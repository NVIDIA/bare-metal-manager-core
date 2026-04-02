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

use clap::Parser;
use nico_rpc::forge;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[clap(short = 'n', long, help = "name of the partition")]
    pub name: String,
    #[clap(short = 't', long, help = "tenant organization id of the partition")]
    pub tenant_organization_id: String,
}

impl From<Args> for forge::NvLinkLogicalPartitionCreationRequest {
    fn from(args: Args) -> Self {
        let metadata = forge::Metadata {
            name: args.name,
            labels: vec![forge::Label {
                key: "cloud-unsafe-op".to_string(),
                value: Some("true".to_string()),
            }],
            ..Default::default()
        };
        Self {
            config: Some(forge::NvLinkLogicalPartitionConfig {
                metadata: Some(metadata),
                tenant_organization_id: args.tenant_organization_id,
            }),
            id: None,
        }
    }
}
