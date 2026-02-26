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

use super::super::common::ExtensionServiceType;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(
        short = 'i',
        long,
        help = "The extension service ID to show (leave empty to show all)"
    )]
    pub id: Option<String>,

    #[clap(short = 't', long = "type", help = "Filter by service type (optional)")]
    pub service_type: Option<ExtensionServiceType>,

    #[clap(short = 'n', long = "name", help = "Filter by service name (optional)")]
    pub service_name: Option<String>,

    #[clap(
        short = 'o',
        long,
        help = "Filter by tenant organization ID (optional)"
    )]
    pub tenant_organization_id: Option<String>,
}
