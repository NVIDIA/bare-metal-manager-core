/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::net::IpAddr;

use uuid::Uuid;

use console::ConsoleError;
use rpc::forge::UserRoles;

use crate::auth;

#[derive(Debug, Clone)]
pub struct IpmiInfo {
    pub ip: IpAddr,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub id: Uuid,
    pub ipmi_info: Option<IpmiInfo>,
}

impl IpmiInfo {
    async fn new(id: Uuid, role: UserRoles, api_endpoint: String) -> Result<Self, ConsoleError> {
        auth::get_bmc_metadata(id, role, api_endpoint).await
    }
}

impl HostInfo {
    pub async fn new(
        data: String,
        role: UserRoles,
        api_endpoint: String,
    ) -> Result<Self, ConsoleError> {
        let uid: Uuid = Uuid::parse_str(&data).map_err(ConsoleError::from)?;
        let mut host_info = HostInfo {
            id: uid,
            ipmi_info: None,
        };

        let ipmi_info = IpmiInfo::new(host_info.id, role, api_endpoint).await?;
        host_info.ipmi_info = Some(ipmi_info);
        Ok(host_info)
    }
}
