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

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{IntoResponse, Response};
use http::{StatusCode, header::CONTENT_TYPE};

use crate::api::Api;

/// Serves the Vault PKI CA/intermediate certificate for the given fabric.
/// Used by UFM's `cert_auto_refresh` feature to pull the latest CA chain.
pub async fn ca_cert(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(fabric): AxumPath<String>,
) -> Response {
    let alt_names = ufm_alt_names(&api, &fabric);

    match api
        .certificate_provider
        .get_certificate(fabric.as_str(), Some(alt_names), Some("365d".to_string()))
        .await
    {
        Ok(certificate) => (
            StatusCode::OK,
            [(CONTENT_TYPE, "application/x-pem-file")],
            String::from_utf8_lossy(&certificate.issuing_ca).into_owned(),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(%err, %fabric, "failed to generate UFM CA certificate");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Serves a freshly-issued server certificate + private key for the given fabric.
/// Used by UFM's `cert_auto_refresh` feature to pull a new server cert before expiry.
pub async fn server_cert(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(fabric): AxumPath<String>,
) -> Response {
    let alt_names = ufm_alt_names(&api, &fabric);

    match api
        .certificate_provider
        .get_certificate(fabric.as_str(), Some(alt_names), Some("365d".to_string()))
        .await
    {
        Ok(certificate) => {
            let body = format!(
                "{}{}",
                String::from_utf8_lossy(&certificate.public_key),
                String::from_utf8_lossy(&certificate.private_key),
            );
            (
                StatusCode::OK,
                [(CONTENT_TYPE, "application/x-pem-file")],
                body,
            )
                .into_response()
        }
        Err(err) => {
            tracing::error!(%err, %fabric, "failed to generate UFM server certificate");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn ufm_alt_names(api: &Api, fabric: &str) -> String {
    if let Some(value) = &api.runtime_config.initial_domain_name {
        format!("{fabric}.ufm.forge, {fabric}.ufm.{value}")
    } else {
        format!("{fabric}.ufm.forge")
    }
}
