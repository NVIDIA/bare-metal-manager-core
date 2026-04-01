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

use std::str::FromStr;

use carbide_uuid::power_shelf::PowerShelfId;
use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(help = "Power shelf ID or name to show (leave empty for all)")]
    pub identifier: Option<String>,
}

impl From<Args> for ::rpc::forge::PowerShelfQuery {
    fn from(args: Args) -> Self {
        match args.identifier {
            Some(id) if !id.is_empty() => {
                // Try to parse as PowerShelfId, otherwise treat as name.
                match PowerShelfId::from_str(&id) {
                    Ok(power_shelf_id) => Self {
                        name: None,
                        power_shelf_id: Some(power_shelf_id),
                    },
                    Err(_) => Self {
                        name: Some(id),
                        power_shelf_id: None,
                    },
                }
            }
            _ => Self {
                name: None,
                power_shelf_id: None,
            },
        }
    }
}
