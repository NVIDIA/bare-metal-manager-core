/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

pub enum Method {
    Get,
    Post,
}

impl Method {
    fn to_string(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

pub fn add_mock(
    server: &mut mockito::ServerGuard,
    path: &str,
    response_body: &str,
    method: &Method,
    status_code: usize,
) -> String {
    // Create a mock
    server
        .mock(method.to_string(), path)
        .with_status(status_code)
        .with_header("content-type", "application/json")
        .with_body(response_body)
        .create();

    format!("{}{}", server.url(), path)
}

pub async fn create_mock_http_server() -> mockito::ServerGuard {
    // Request a new server from the pool
    mockito::Server::new_async().await
}
