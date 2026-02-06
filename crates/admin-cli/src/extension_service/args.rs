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
use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Create an extension service")]
    Create(CreateExtensionService),
    #[clap(about = "Update an extension service")]
    Update(UpdateExtensionService),
    #[clap(about = "Delete an extension service")]
    Delete(DeleteExtensionService),
    #[clap(about = "Show extension service information")]
    Show(ShowExtensionService),
    #[clap(about = "Get extension service version information")]
    GetVersion(GetExtensionServiceVersionInfo),
    #[clap(about = "Show instances using an extension service")]
    ShowInstances(ShowExtensionServiceInstances),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab_case")]
#[repr(i32)]
pub enum ExtensionServiceType {
    #[value(alias = "k8s")]
    KubernetesPod = 0, // Kubernetes pod service type
}

impl From<ExtensionServiceType> for i32 {
    fn from(v: ExtensionServiceType) -> Self {
        v as i32
    }
}

#[derive(Parser, Debug, Clone)]
pub struct CreateExtensionService {
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

#[derive(Parser, Debug)]
pub struct UpdateExtensionService {
    #[clap(short = 'i', long = "id", help = "The extension service ID to update")]
    pub service_id: String,

    #[clap(
        short = 'n',
        long = "name",
        help = "New extension service name (optional)"
    )]
    pub service_name: Option<String>,

    #[clap(long, help = "New extension service description (optional)")]
    pub description: Option<String>,

    #[clap(short = 'd', long, help = "New extension service data")]
    pub data: String,

    #[clap(long, help = "New registry URL for the service credential (optional)")]
    pub registry_url: Option<String>,

    #[clap(
        short = 'u',
        long,
        help = "New username for the service credential (optional)"
    )]
    pub username: Option<String>,

    #[clap(
        short = 'p',
        long,
        help = "New password for the service credential (optional)"
    )]
    pub password: Option<String>,

    #[clap(
        long,
        help = "Update only if current number of versions matches this number (optional)"
    )]
    pub if_version_ctr_match: Option<i32>,

    #[clap(
        long,
        help = "JSON array containing a defined set of extension observability configs (optional)"
    )]
    pub observability: Option<String>,
}

#[derive(Parser, Debug)]
pub struct DeleteExtensionService {
    #[clap(short = 'i', long = "id", help = "The extension service ID to delete")]
    pub service_id: String,

    #[clap(
        short = 'v',
        long,
        help = "Version strings to delete (optional, leave empty to keep all versions)",
        value_delimiter = ','
    )]
    pub versions: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct ShowExtensionService {
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

#[derive(Parser, Debug)]
pub struct GetExtensionServiceVersionInfo {
    #[clap(short = 'i', long, help = "The extension service ID")]
    pub service_id: String,

    #[clap(
        short = 'v',
        long,
        help = "Version strings to get (optional, leave empty to get all versions)",
        value_delimiter = ','
    )]
    pub versions: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct ShowExtensionServiceInstances {
    #[clap(short = 'i', long, help = "The extension service ID")]
    pub service_id: String,

    #[clap(short = 'v', long, help = "Version string to filter by (optional)")]
    pub version: Option<String>,
}
