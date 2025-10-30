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
use ::rpc::protos::forge::MachineCertificate;
use async_trait::async_trait;

use crate::SecretsError;

#[derive(Debug, Clone, Default)]
pub struct Certificate {
    pub issuing_ca: Vec<u8>,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl From<Certificate> for MachineCertificate {
    fn from(value: Certificate) -> Self {
        MachineCertificate {
            issuing_ca: value.issuing_ca,
            private_key: value.private_key,
            public_key: value.public_key,
        }
    }
}

#[async_trait]
pub trait CertificateProvider: Send + Sync {
    async fn get_certificate(
        &self,
        unique_identifier: &str,
        alt_names: Option<String>,
        ttl: Option<String>,
    ) -> Result<Certificate, SecretsError>;
}
