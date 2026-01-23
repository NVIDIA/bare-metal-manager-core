/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum OpCode {
    Noop,
    Unlock { key: String },
    ApplyProfile { profile_str: String },
    Lock { key: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DpaCommand {
    pub op: OpCode,
}
