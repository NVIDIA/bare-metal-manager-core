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

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{DriverOutcome, OpCx, PlatformError};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleId {
    Administrator,
    Operator,
    ReadOnly,
    NoAccess,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub id: Option<String>,
    pub username: String,
    pub role_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub locked: Option<bool>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AccountCreate {
    pub username: String,
    pub password: String,
    pub role: RoleId,
}

impl fmt::Debug for AccountCreate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountCreate")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("role", &self.role)
            .finish()
    }
}

/// BMC local-account and account-policy operations.
#[async_trait]
pub trait Accounts: Send + Sync {
    async fn list(&self, cx: &OpCx<'_>) -> Result<Vec<Account>, PlatformError>;

    async fn create(
        &self,
        cx: &OpCx<'_>,
        request: &AccountCreate,
    ) -> Result<DriverOutcome, PlatformError>;

    async fn delete(&self, cx: &OpCx<'_>, username: &str) -> Result<DriverOutcome, PlatformError>;

    async fn change_password(
        &self,
        cx: &OpCx<'_>,
        username: &str,
        password: &str,
    ) -> Result<DriverOutcome, PlatformError>;

    async fn change_password_by_id(
        &self,
        cx: &OpCx<'_>,
        account_id: &str,
        password: &str,
    ) -> Result<DriverOutcome, PlatformError>;

    async fn change_username(
        &self,
        cx: &OpCx<'_>,
        old_username: &str,
        new_username: &str,
    ) -> Result<DriverOutcome, PlatformError>;

    async fn apply_default_policy(&self, cx: &OpCx<'_>) -> Result<DriverOutcome, PlatformError>;
}
