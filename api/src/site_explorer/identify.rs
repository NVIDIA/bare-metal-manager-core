/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::time::Duration;

use thiserror::Error;

use crate::model::hardware_info::BMCVendor;

#[derive(Error, Debug)]
pub enum IdentifyError {
    #[error("{0} did not return a TLS certificate")]
    NoCertificate(String),

    #[error("{0} returned an invalid x509 cert")]
    InvalidCertificate(String),

    #[error("TLS cert for {0} did not contain an Organization field")]
    MissingOrganizationField(String),

    #[error(transparent)]
    HTTPError(#[from] reqwest::Error),
}

impl From<IdentifyError> for tonic::Status {
    fn from(e: IdentifyError) -> tonic::Status {
        use IdentifyError::*;
        match e {
            NoCertificate(_) => tonic::Status::unavailable(e.to_string()),
            InvalidCertificate(_) => tonic::Status::internal(e.to_string()),
            MissingOrganizationField(_) => tonic::Status::internal(e.to_string()),
            HTTPError(_) => tonic::Status::internal(e.to_string()),
        }
    }
}

// Inspect the BMC's TLS certificate to identify the vendor
pub async fn identify_bmc(address: &str) -> Result<(String, BMCVendor), IdentifyError> {
    let url = if address.starts_with("https") {
        address.to_string()
    } else {
        format!("https://{address}")
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .use_rustls_tls()
        .tls_info(true)
        .timeout(Duration::from_secs(2))
        .https_only(true)
        .build()?;
    let response = client.head(&url).send().await?;

    let tls_info = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .unwrap();
    let Some(cert) = tls_info.peer_certificate() else {
        return Err(IdentifyError::NoCertificate(url));
    };
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(cert) else {
        return Err(IdentifyError::InvalidCertificate(url));
    };
    let mut organization = None;
    for rdn in certificate.issuer().iter_organization() {
        if let Ok(org_name) = rdn.as_str() {
            organization = Some(org_name);
            break;
        }
    }
    match organization {
        None => Err(IdentifyError::MissingOrganizationField(url)),
        Some(org) => Ok((org.to_string(), BMCVendor::from_tls_issuer(org))),
    }
}
