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

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(long, help = "Filter by firmware ID")]
    pub firmware_id: Option<String>,

    #[clap(long, help = "Filter by rack ID(s)")]
    pub rack_id: Vec<String>,
}

impl From<Args> for rpc::forge::RackFirmwareHistoryRequest {
    fn from(args: Args) -> Self {
        Self {
            firmware_id: args.firmware_id.unwrap_or_default(),
            rack_ids: args.rack_id,
        }
    }
}
