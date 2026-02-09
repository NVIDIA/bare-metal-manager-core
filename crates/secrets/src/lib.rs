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
