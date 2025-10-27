/*
 *   SPDX-FileCopyrightText: Copyright (c) 2022-2022. NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *   SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 *   NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 *   property and proprietary rights in and to this material, related
 *   documentation and any modifications thereto. Any use, reproduction,
 *   disclosure or distribution of this material and related documentation
 *   without an express license agreement from NVIDIA CORPORATION or
 *   its affiliates is strictly prohibited.
 */

pub const PATH: &str = "etc/frr/daemons";
const TMPL_FULL: &str = include_str!("../templates/daemons");
pub const RESTART_CMD: &str = "supervisorctl restart frr";

/// Generate /etc/frr/daemons. It has no templated parts.
pub fn build() -> String {
    TMPL_FULL.to_string()
}
