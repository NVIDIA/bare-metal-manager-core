/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::str::FromStr;

use axum::http::{uri::PathAndQuery, Request, Uri};

pub mod logging;
pub mod metrics;

pub async fn normalize_url<B>(mut request: Request<B>) -> Request<B> {
    let uri = request.uri_mut();
    if let Some(p_q) = uri.path_and_query() {
        let path_and_query = p_q.to_string();
        let removed_duplicated_slashes = path_and_query.as_str().replace("//", "/");
        let new_path_and_query = match PathAndQuery::from_str(removed_duplicated_slashes.as_str()) {
            Ok(path_and_query) => path_and_query,
            _ => unreachable!(),
        };
        *uri = Uri::from(new_path_and_query);
    }
    request
}

#[cfg(test)]
mod test {
    use super::*;
    #[tokio::test]
    pub async fn test_url_normalize() {
        let request = Request::builder()
            .uri("http://localhost:8080/api/v0/cloud-init//user-data")
            .body(())
            .unwrap();
        let result = normalize_url(request).await;
        assert_eq!(result.uri().path(), "/api/v0/cloud-init/user-data");
    }
}
