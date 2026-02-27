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

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[clap(
        short = 'i',
        long = "id",
        help = "The extension service ID to create (optional)"
    )]
    pub service_id: Option<String>,

    #[clap(short = 'n', long = "name", help = "Extension service name")]
    pub service_name: String,

    #[clap(short = 't', long = "type", help = "Extension service type")]
    pub service_type: ExtensionServiceType,

    #[clap(long, help = "Extension service description (optional)")]
    pub description: Option<String>,

    #[clap(long, help = "Tenant organization ID")]
    pub tenant_organization_id: Option<String>,

    #[clap(short = 'd', long, help = "Extension service data")]
    pub data: String,

    #[clap(long, help = "Registry URL for the service credential (optional)")]
    pub registry_url: Option<String>,

    #[clap(long, help = "Username for the service credential (optional)")]
    pub username: Option<String>,

    #[clap(long, help = "Password for the service credential (optional)")]
    pub password: Option<String>,

    #[clap(
        long,
        help = "JSON array containing a defined set of extension observability configs (optional)"
    )]
    pub observability: Option<String>,
}
