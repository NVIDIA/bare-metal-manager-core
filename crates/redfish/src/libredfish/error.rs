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

use forge_secrets::SecretsError;
use libredfish::RedfishError;

#[derive(thiserror::Error, Debug)]
pub enum RedfishClientCreationError {
    #[error("Missing credential {key}")]
    MissingCredentials { key: String },
    #[error("Missing credential: {cause}")]
    SecretEngineError { cause: SecretsError },
    #[error("Failed redfish request {0}")]
    RedfishError(RedfishError),
    #[error("Invalid Header {0}")]
    InvalidHeader(String),
    #[error("Missing Arguments: {0}")]
    MissingArgument(String),
    #[error("Missing BMC Information: {0}")]
    MissingBmcEndpoint(String),
    #[error("Database Error Loading Machine Interface")]
    MachineInterfaceLoadError(#[from] db::DatabaseError),
}

impl From<SecretsError> for RedfishClientCreationError {
    fn from(cause: SecretsError) -> Self {
        RedfishClientCreationError::SecretEngineError { cause }
    }
}
