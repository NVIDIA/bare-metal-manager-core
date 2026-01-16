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
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdnsResponse {
    result: Value,
}

impl PdnsResponse {
    pub fn new(result: serde_json::Value) -> Self {
        PdnsResponse { result }
    }
}

impl From<Value> for PdnsResponse {
    fn from(value: Value) -> Self {
        PdnsResponse { result: value }
    }
}

impl From<Vec<Value>> for PdnsResponse {
    fn from(values: Vec<Value>) -> Self {
        PdnsResponse {
            result: Value::Array(values),
        }
    }
}
