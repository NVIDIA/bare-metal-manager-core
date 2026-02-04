/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::borrow::Cow;
use std::fmt::Display;

use axum::Router;
use axum::extract::Path;
use axum::response::Response;
use axum::routing::get;
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::JsonExt;
use crate::redfish;

pub fn resource() -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Borrowed("/redfish/v1/AccountService"),
        odata_type: Cow::Borrowed("#AccountService.v1_9_0.AccountService"),
        id: Cow::Borrowed("AccountService"),
        name: Cow::Borrowed("Account Service"),
    }
}

pub fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
    r.route(&resource().odata_id, get(get_root))
        .route(&ACCOUNTS_COLLECTION_RESOURCE.odata_id, get(get_accounts))
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

pub fn account_resource(id: impl Display) -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Owned(format!("{}/{id}", ACCOUNTS_COLLECTION_RESOURCE.odata_id)),
        odata_type: Cow::Borrowed("#ManagerAccount.v1_8_0.ManagerAccount"),
        name: Cow::Borrowed("User Account"),
        id: Cow::Owned(id.to_string()),
    }
}

pub async fn get_accounts() -> Response {
    // This is Dell-specific behavior of Account handling. Fixed slots...
    let members = (1..16)
        .map(|v| json!({"@odata.id": format!("{}/{v}", ACCOUNTS_COLLECTION_RESOURCE.odata_id)}))
        .collect::<Vec<_>>();
    ACCOUNTS_COLLECTION_RESOURCE
        .with_members(&members)
        .into_ok_response()
}

pub async fn patch_account(Path(_account_id): Path<String>) -> Response {
    json!({}).into_ok_response()
}

pub async fn get_account(Path(account_id): Path<String>) -> Response {
    // This is Dell behavior must be fixed for other platform.
    let (username, role_id) = if account_id == "2" {
        ("root", "Administrator")
    } else {
        ("", "")
    };
    json!({
        "UserName": username,
        "RoleId": role_id,
        "AccountTypes": ["Redfish"]
    })
    .patch(account_resource(account_id))
    .into_ok_response()
}
