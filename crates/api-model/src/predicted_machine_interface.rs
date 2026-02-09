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
use carbide_uuid::machine::MachineId;
use mac_address::MacAddress;
use sqlx::FromRow;
use uuid::Uuid;

use crate::network_segment::NetworkSegmentType;

#[derive(Debug, Clone, FromRow)]
pub struct PredictedMachineInterface {
    pub id: Uuid,
    pub machine_id: MachineId,
    pub mac_address: MacAddress,
    pub expected_network_segment_type: NetworkSegmentType,
}

#[derive(Debug, Clone)]
pub struct NewPredictedMachineInterface<'a> {
    pub machine_id: &'a MachineId,
    pub mac_address: MacAddress,
    pub expected_network_segment_type: NetworkSegmentType,
}
