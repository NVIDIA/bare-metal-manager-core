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

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum TenantRoutingProfileType {
    // Admin variant is an implicit profile of the admin network VPC
    // and is not a valid value, and so it can/should be omitted.
    Internal,
    PrivilegedInternal,
    External,
    Maintenance,
}

impl From<TenantRoutingProfileType> for rpc::forge::RoutingProfileType {
    fn from(p: TenantRoutingProfileType) -> Self {
        match p {
            TenantRoutingProfileType::Internal => rpc::forge::RoutingProfileType::Internal,
            TenantRoutingProfileType::PrivilegedInternal => {
                rpc::forge::RoutingProfileType::PrivilegedInternal
            }
            TenantRoutingProfileType::External => rpc::forge::RoutingProfileType::External,
            TenantRoutingProfileType::Maintenance => rpc::forge::RoutingProfileType::Maintenance,
        }
    }
}
