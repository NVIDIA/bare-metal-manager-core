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

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;

pub trait JsonExt {
    fn patch(self, patch: impl JsonPatch) -> serde_json::Value
    where
        Self: Sized;

    fn delete_fields(self, fields: &[&str]) -> serde_json::Value
    where
        Self: Sized;

    fn into_ok_response(self) -> Response<Body>
    where
        Self: Sized + ToString,
    {
        self.into_response(StatusCode::OK)
    }

    fn into_response(self, status: StatusCode) -> Response<Body>
    where
        Self: Sized + ToString;

    fn into_ok_response_with_location(self, location: HeaderValue) -> Response<Body>
    where
        Self: Sized + ToString,
    {
        let mut response = self.into_ok_response();
        response.headers_mut().insert("Location", location);
        response
    }
}

impl JsonExt for serde_json::Value {
    fn patch(mut self, patch: impl JsonPatch) -> serde_json::Value {
        json_patch(&mut self, patch.json_patch());
        self
    }

    fn delete_fields(mut self, fields: &[&str]) -> serde_json::Value {
        if let serde_json::Value::Object(obj) = &mut self {
            for f in fields {
                obj.remove(*f);
            }
        }
        self
    }

    fn into_response(self, status: StatusCode) -> Response<Body>
    where
        Self: Sized + ToString,
    {
        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Body::from(self.to_string()))
            .unwrap()
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
