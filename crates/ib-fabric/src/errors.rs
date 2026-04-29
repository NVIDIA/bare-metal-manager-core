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

use db::DatabaseError;
use model::errors::ModelError;

#[derive(thiserror::Error, Debug)]
pub enum IbError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] DatabaseError),
    #[error("Model error: {0}")]
    ModelError(#[from] ModelError),
    #[error("Failed to call IBFabricManager: {0}")]
    IBFabricError(String),
    #[error("{kind} not found: {id}")]
    NotFoundError {
        /// The type of the resource that was not found (e.g. Machine)
        kind: &'static str,
        /// The ID of the resource that was not found
        id: String,
    },
    #[error("Argument is invalid: {0}")]
    InvalidArgument(String),
    #[error("The function is not implemented")]
    NotImplemented,
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl IbError {
    /// Creates a `Internal` error with the given error message
    pub fn internal(message: String) -> Self {
        Self::Internal { message }
    }
}

pub type IbResult<T> = Result<T, IbError>;
