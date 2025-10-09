/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge::forge_server::Forge;
use rpc::forge::RedfishAction;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::auth::{AuthContext, ExternalUserInfo};
use crate::db;
use crate::tests::common::api_fixtures::{TestEnv, create_managed_host, create_test_env};

#[crate::sqlx_test]
async fn test_create_and_approve_action(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;
    let bmc_ip = mh
        .host()
        .rpc_machine()
        .await
        .bmc_info
        .as_ref()
        .unwrap()
        .ip()
        .to_string();

    let request = ::rpc::forge::RedfishCreateActionRequest {
        ips: vec![bmc_ip.clone()],
        action: "#ComputerSystem.Reset".to_string(),
        target: "/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset".to_string(),
        parameters: r#"{"ResetType":"ForceOff"}"#.to_string(),
    };

    let response = env
        .api
        .redfish_create_action(request_with_username("user1", request.clone()))
        .await
        .unwrap()
        .into_inner();
    let request_id = response.request_id;

    let mut actions = list_actions(&env, Some(bmc_ip.clone())).await;
    assert_eq!(actions.len(), 1);
    let action = actions.remove(0);
    assert_eq!(action.request_id, request_id);
    assert_eq!(action.target, request.target);
    assert_eq!(action.parameters, request.parameters);
    assert_eq!(action.action, request.action);
    assert_eq!(&action.requester, "user1");
    assert_eq!(action.approvers, vec!["user1".to_string()]);
    assert_eq!(
        action.results,
        vec![::rpc::forge::OptionalRedfishActionResult { result: None }]
    );

    // Trying to apply the action without approvals fails
    let err = env
        .api
        .redfish_apply_action(request_with_username(
            "user1",
            rpc::forge::RedfishActionId { request_id },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(err.message(), "insufficient approvals");

    // Try to approve again with same username
    let err = env
        .api
        .redfish_approve_action(request_with_username(
            "user1",
            rpc::forge::RedfishActionId { request_id },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(err.message(), "user already approved request");

    // Approve by second user is ok
    env.api
        .redfish_approve_action(request_with_username(
            "user2",
            rpc::forge::RedfishActionId { request_id },
        ))
        .await
        .unwrap()
        .into_inner();
    let mut actions = list_actions(&env, Some(bmc_ip.clone())).await;
    assert_eq!(actions.len(), 1);
    let action = actions.remove(0);
    assert_eq!(
        action.approvers,
        vec!["user2".to_string(), "user1".to_string()]
    );
    assert_eq!(
        action.results,
        vec![::rpc::forge::OptionalRedfishActionResult { result: None }]
    );

    // Approve by second user again
    let err = env
        .api
        .redfish_approve_action(request_with_username(
            "user2",
            rpc::forge::RedfishActionId { request_id },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(err.message(), "user already approved request");

    // Test whether the raw DB query allows double insertion of approver
    let mut txn = env.db_txn().await;
    assert!(
        !db::redfish_actions::approve_request("user2".to_string(), request_id.into(), &mut txn)
            .await
            .unwrap()
    );
    txn.commit().await.unwrap();

    let mut actions = list_actions(&env, Some(bmc_ip.clone())).await;
    assert_eq!(actions.len(), 1);
    let action = actions.remove(0);
    assert_eq!(
        action.approvers,
        vec!["user2".to_string(), "user1".to_string()]
    );

    // We don't apply the action here. The current implementation will send off a HTTP request
    // to the target IP - and that might cause side-effects.
    // TODO: Test successful apply and results later.
}

async fn list_actions(env: &TestEnv, bmc_ip: Option<String>) -> Vec<RedfishAction> {
    env.api
        .redfish_list_actions(tonic::Request::new(
            ::rpc::forge::RedfishListActionsRequest { machine_ip: bmc_ip },
        ))
        .await
        .unwrap()
        .into_inner()
        .actions
}

fn request_with_username<T>(user: &str, request: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(request);

    let mut auth_context = AuthContext::default();
    auth_context
        .principals
        .push(crate::auth::Principal::ExternalUser(ExternalUserInfo {
            org: Some("test_org".to_string()),
            group: "test_group".to_string(),
            user: Some(user.to_string()),
        }));

    request.extensions_mut().insert(auth_context);

    request
}
