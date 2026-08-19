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

use bmc_mock::{HardwareType, RackPlacement, RackType};
use carbide_uuid::rack::{RackId, RackProfileId};
use serde::Serialize;

use crate::status::DeviceStatus;

#[derive(Clone, Debug)]
pub(crate) struct RackMemberRegistration {
    pub placement: RackPlacement,
    pub hardware_type: HardwareType,
    pub machine_config_section: String,
}

#[derive(Clone, Debug)]
pub(crate) struct RackRegistration {
    pub rack_id: RackId,
    pub rack_profile_id: RackProfileId,
    pub rack_type: RackType,
    pub version: u32,
    pub members: Vec<RackMemberRegistration>,
}

#[derive(Clone, Debug)]
pub(crate) struct RackMemberRef {
    pub placement: RackPlacement,
    pub device_index: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct RackInstance {
    pub rack_id: RackId,
    pub rack_type: RackType,
    pub version: u32,
    pub members: Vec<RackMemberRef>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RacksStatusResponse {
    pub racks: Vec<RackStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RackStatus {
    pub rack_id: String,
    pub rack_type: RackType,
    pub version: u32,
    pub members: Vec<RackMemberStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RackMemberStatus {
    pub position: u8,
    #[serde(flatten)]
    pub device: DeviceStatus,
}
