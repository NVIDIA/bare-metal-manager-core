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

use std::borrow::Cow;
use std::fmt::Display;
use std::sync::{Arc, Mutex, Weak};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use futures::future::BoxFuture;
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::JsonExt;
use crate::{http, redfish};

pub fn resource() -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Borrowed("/redfish/v1/AccountService"),
        odata_type: Cow::Borrowed("#AccountService.v1_9_0.AccountService"),
        id: Cow::Borrowed("AccountService"),
        name: Cow::Borrowed("Account Service"),
    }
}

pub fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
    r.route(&resource().odata_id, get(get_root).patch(patch_root))
        .route(
            &ACCOUNTS_COLLECTION_RESOURCE.odata_id,
            get(get_accounts).post(create_account),
        )
        .route(
            format!("{}/{{account_id}}", ACCOUNTS_COLLECTION_RESOURCE.odata_id).as_str(),
            get(get_account).patch(patch_account),
        )
}

const ACCOUNTS_COLLECTION_RESOURCE: redfish::Collection<'static> = redfish::Collection {
    odata_id: Cow::Borrowed("/redfish/v1/AccountService/Accounts"),
    odata_type: Cow::Borrowed("#ManagerAccountCollection.ManagerAccountCollection"),
    name: Cow::Borrowed("Accounts Collection"),
};
const ADMINISTRATOR_ROLE_ID: &str = "Administrator";

#[derive(Debug)]
pub struct AccountServiceState {
    accounts: Mutex<Vec<Account>>,
    password_updater: Mutex<Option<Weak<dyn PasswordUpdater>>>,
}

pub(crate) trait PasswordUpdater: Send + Sync {
    fn update_password<'a>(
        &'a self,
        username: &'a str,
        current_password: &'a str,
        new_password: &'a str,
    ) -> BoxFuture<'a, Result<(), String>>;
}

impl AccountServiceState {
    pub fn new(factory_default_account: Account) -> Self {
        Self {
            accounts: Mutex::new(vec![factory_default_account]),
            password_updater: Mutex::new(None),
        }
    }

    pub(crate) fn set_password_updater(&self, updater: &Arc<dyn PasswordUpdater>) {
        *self.password_updater.lock().expect("mutex poisoned") = Some(Arc::downgrade(updater));
    }

    pub fn accounts(&self) -> Vec<Account> {
        self.accounts.lock().expect("mutex poisoned").clone()
    }

    pub fn find(&self, account_id: &str) -> Option<Account> {
        self.accounts
            .lock()
            .expect("mutex poisoned")
            .iter()
            .find(|account| account.id == account_id)
            .cloned()
    }

    pub(crate) fn administrator_credentials(&self) -> Option<(String, String)> {
        self.accounts
            .lock()
            .expect("mutex poisoned")
            .iter()
            .find(|account| account.role_id == ADMINISTRATOR_ROLE_ID)
            .map(|account| (account.username.clone(), account.password.clone()))
    }

    pub fn is_authorized(&self, username: &str, password: &str) -> bool {
        self.accounts
            .lock()
            .expect("mutex poisoned")
            .iter()
            .any(|account| account.matches(username, password))
    }

    pub fn is_factory_default_password(&self, username: &str, password: &str) -> bool {
        self.accounts
            .lock()
            .expect("mutex poisoned")
            .iter()
            .any(|account| account.matches_factory_default_password(username, password))
    }

    pub async fn update_password(
        &self,
        account_id: &str,
        password: impl Into<String>,
    ) -> Result<bool, String> {
        let password = password.into();
        let account = self.find(account_id);
        let Some(account) = account else {
            return Ok(false);
        };
        let updater = self
            .password_updater
            .lock()
            .expect("mutex poisoned")
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(updater) = updater {
            updater
                .update_password(&account.username, &account.password, &password)
                .await?;
        }

        let mut accounts = self.accounts.lock().expect("mutex poisoned");
        let account = accounts
            .iter_mut()
            .find(|candidate| candidate.id == account_id)
            .expect("account existed before password synchronization");
        account.password = password;
        Ok(true)
    }

    /// Rotates every account on its factory default password to `new_password`
    pub fn change_factory_default_password(&self, new_password: impl Into<String>) {
        let new_password = new_password.into();
        let mut accounts = self.accounts.lock().expect("mutex poisoned");
        for account in accounts.iter_mut() {
            if account.password == account.factory_default_password {
                account.password = new_password.clone();
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    id: String,
    username: String,
    password: String,
    factory_default_password: String,
    role_id: String,
}

impl Account {
    pub fn administrator(
        id: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        let password = password.into();
        Self {
            id: id.into(),
            username: username.into(),
            password: password.clone(),
            factory_default_password: password,
            role_id: ADMINISTRATOR_ROLE_ID.into(),
        }
    }

    fn matches(&self, username: &str, password: &str) -> bool {
        self.username == username && self.password == password
    }

    fn matches_factory_default_password(&self, username: &str, password: &str) -> bool {
        self.matches(username, password) && self.password == self.factory_default_password
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "UserName": self.username,
            "RoleId": self.role_id,
            "AccountTypes": ["Redfish"]
        })
        .patch(account_resource(&self.id))
    }
}

pub async fn get_root() -> Response {
    let service_attrs = json!({
        "AccountLockoutCounterResetAfter": 0,
        "AccountLockoutDuration": 0,
        "AccountLockoutThreshold": 0,
        "AuthFailureLoggingThreshold": 2,
        "LocalAccountAuth": "Fallback",
        "MaxPasswordLength": 40,
        "MinPasswordLength": 0,
    });
    service_attrs
        .patch(resource())
        .patch(ACCOUNTS_COLLECTION_RESOURCE.nav_property("Accounts"))
        .into_ok_response()
}

pub async fn patch_root() -> Response {
    http::ok_no_content()
}

pub fn account_resource(id: impl Display) -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Owned(format!("{}/{id}", ACCOUNTS_COLLECTION_RESOURCE.odata_id)),
        odata_type: Cow::Borrowed("#ManagerAccount.v1_8_0.ManagerAccount"),
        name: Cow::Borrowed("User Account"),
        id: Cow::Owned(id.to_string()),
    }
}

pub async fn get_accounts(State(state): State<BmcState>) -> Response {
    let members = state
        .account_service_state
        .accounts()
        .iter()
        .map(|account| account_resource(&account.id).entity_ref())
        .collect::<Vec<_>>();
    ACCOUNTS_COLLECTION_RESOURCE
        .with_members(&members)
        .into_ok_response()
}

pub async fn create_account() -> Response {
    json!({}).into_ok_response()
}

pub async fn patch_account(
    State(state): State<BmcState>,
    Path(account_id): Path<String>,
    Json(patch_account): Json<serde_json::Value>,
) -> Response {
    let Some(password) = patch_account
        .get("Password")
        .and_then(serde_json::Value::as_str)
    else {
        return json!("Password must be a string").into_response(StatusCode::BAD_REQUEST);
    };

    match state
        .account_service_state
        .update_password(&account_id, password)
        .await
    {
        Ok(true) => http::ok_no_content(),
        Ok(false) => http::not_found(),
        Err(error) => {
            tracing::error!(%error, %account_id, "failed to synchronize BMC account password");
            json!("Failed to synchronize BMC account password")
                .into_response(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn get_account(
    State(state): State<BmcState>,
    Path(account_id): Path<String>,
) -> Response {
    state
        .account_service_state
        .find(&account_id)
        .map(|account| account.to_json().into_ok_response())
        .unwrap_or_else(http::not_found)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures::future::BoxFuture;

    use super::{Account, AccountServiceState, PasswordUpdater};

    struct TestPasswordUpdater {
        result: Result<(), String>,
    }

    impl PasswordUpdater for TestPasswordUpdater {
        fn update_password<'a>(
            &'a self,
            _username: &'a str,
            _current_password: &'a str,
            _new_password: &'a str,
        ) -> BoxFuture<'a, Result<(), String>> {
            let result = self.result.clone();
            Box::pin(async move { result })
        }
    }

    fn state_with_updater(
        result: Result<(), String>,
    ) -> (AccountServiceState, Arc<dyn PasswordUpdater>) {
        let state = AccountServiceState::new(Account::administrator("1", "root", "old-password"));
        let updater: Arc<dyn PasswordUpdater> = Arc::new(TestPasswordUpdater { result });
        state.set_password_updater(&updater);
        (state, updater)
    }

    #[tokio::test]
    async fn update_password_commits_after_ipmi_update_succeeds() {
        let (state, _updater) = state_with_updater(Ok(()));

        assert_eq!(state.update_password("1", "new-password").await, Ok(true));
        assert!(state.is_authorized("root", "new-password"));
    }

    #[tokio::test]
    async fn update_password_preserves_redfish_password_when_ipmi_update_fails() {
        let (state, _updater) = state_with_updater(Err("IPMI update failed".to_string()));

        assert_eq!(
            state.update_password("1", "new-password").await,
            Err("IPMI update failed".to_string())
        );
        assert!(state.is_authorized("root", "old-password"));
        assert!(!state.is_authorized("root", "new-password"));
    }
}
