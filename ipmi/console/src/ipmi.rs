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
    pub machine_id: Uuid,
    pub user_role: UserRoles,
}

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub id: Uuid,
    pub ipmi_info: IpmiInfo,
}

impl HostInfo {
    pub async fn new(
        data: String,
        role: UserRoles,
        api_endpoint: String,
    ) -> Result<Self, ConsoleError> {
        let uid: Uuid = Uuid::parse_str(&data).map_err(ConsoleError::from)?;
        // TODO: we literally only need the IP address here, so that should move into its own call
        // TODO: on the carbide API so that we're not grabbing the credentials and throwing them away.
        let bmc_metadata = auth::get_bmc_metadata(uid, role, api_endpoint).await?;
        let host_info = HostInfo {
            id: uid,
            ipmi_info: IpmiInfo {
                ip: bmc_metadata.ip.parse()?,
                machine_id: uid,
                user_role: role,
            },
        };

        Ok(host_info)
    }
}
