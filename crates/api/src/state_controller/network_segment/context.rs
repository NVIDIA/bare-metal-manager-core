/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::state_controller::common_services::CommonStateHandlerServices;
use crate::state_controller::network_segment::metrics::NetworkSegmentMetrics;
use crate::state_controller::state_handler::StateHandlerContextObjects;

pub struct NetworkSegmentStateHandlerContextObjects {}

impl StateHandlerContextObjects for NetworkSegmentStateHandlerContextObjects {
    type Services = CommonStateHandlerServices;
    type ObjectMetrics = NetworkSegmentMetrics;
}
