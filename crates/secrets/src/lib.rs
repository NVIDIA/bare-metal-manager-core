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
use std::fmt::Display;

pub use crate::forge_vault::ForgeVaultClient;

pub mod certificates;
pub mod credentials;
pub mod forge_vault;

#[derive(Debug)]
pub enum SecretsError {
    GenericError(eyre::Report),
}

impl Display for SecretsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretsError::GenericError(report) => {
                write!(f, "Secrets operation failed: {}", report)
            }
        }
    }
}

impl From<eyre::Report> for SecretsError {
    fn from(value: eyre::Report) -> Self {
        SecretsError::GenericError(value)
    }
}

impl From<SecretsError> for eyre::Report {
    fn from(value: SecretsError) -> Self {
        match value {
            SecretsError::GenericError(report) => report,
        }
    }
}
