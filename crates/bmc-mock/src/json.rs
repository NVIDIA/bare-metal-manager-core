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

use axum::http::StatusCode;
use axum::response::IntoResponse;

pub trait JsonExt {
    fn patch(self, patch: impl JsonPatch) -> serde_json::Value
    where
        Self: Sized;

    fn into_ok_response(self) -> impl IntoResponse
    where
        Self: Sized;
}

impl JsonExt for serde_json::Value {
    fn patch(mut self, patch: impl JsonPatch) -> serde_json::Value {
        json_patch(&mut self, patch.json_patch());
        self
    }
    fn into_ok_response(self) -> impl IntoResponse
    where
        Self: Sized + ToString,
    {
        (StatusCode::OK, self.to_string())
    }
}

pub trait JsonPatch {
    fn json_patch(&self) -> serde_json::Value;
}

impl JsonPatch for serde_json::Value {
    fn json_patch(&self) -> serde_json::Value {
        self.clone()
    }
}

pub fn json_patch(target: &mut serde_json::Value, patch: serde_json::Value) {
    match (target, patch) {
        (serde_json::Value::Object(target_obj), serde_json::Value::Object(patch_obj)) => {
            for (k, v_patch) in patch_obj {
                match target_obj.get_mut(&k) {
                    Some(v_target) => json_patch(v_target, v_patch),
                    None => {
                        target_obj.insert(k, v_patch);
                    }
                }
            }
        }
        (target_slot, v_patch) => *target_slot = v_patch,
    }
}
