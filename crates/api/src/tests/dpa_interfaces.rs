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

use rpc::forge::forge_server::Forge;
use rpc::forge::{DpaInterfaceCreationRequest, DpaInterfacesByIdsRequest};

use crate::tests::common::api_fixtures::{create_managed_host, create_test_env};

#[crate::sqlx_test]
async fn dpa_api_test_cases(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // Create a managed host
    // Create an DPA interface with MAC addr "00:11:22:33:44:55" in that managed host
    // Call API routine get_all_dpa_interface_ids and make sure it returns the one and only interface
    // Call API routine find_dpa_interfaces_by_ids and make sure it reurns the one and only interface

    let env = create_test_env(pool).await;

    let mh = create_managed_host(&env).await;

    let cr_request = tonic::Request::new(DpaInterfaceCreationRequest {
        mac_addr: "00:11:22:33:44:55".to_string(),
        machine_id: Some(mh.id),
        device_type: "BlueField3".to_string(),
        pci_name: "0000:cc:00.0".to_string(),
    });

    let cr_resp = env
        .api
        .create_dpa_interface(cr_request)
        .await
        .unwrap()
        .into_inner();

    let intf_id = cr_resp.id.unwrap();

    let get_ids_req = tonic::Request::new(());

    let get_all_resp = env
        .api
        .get_all_dpa_interface_ids(get_ids_req)
        .await
        .unwrap()
        .into_inner();

    assert!(get_all_resp.ids.len() == 1);
    assert!(get_all_resp.ids[0] == intf_id);

    let find_by_id_req = tonic::Request::new(DpaInterfacesByIdsRequest {
        ids: vec![intf_id],
        include_history: false,
    });

    let find_by_id_resp = env
        .api
        .find_dpa_interfaces_by_ids(find_by_id_req)
        .await
        .unwrap()
        .into_inner();

    assert!(find_by_id_resp.interfaces.len() == 1);

    let find_resp = &find_by_id_resp.interfaces[0];

    assert!(find_resp.id.unwrap() == intf_id);
    assert!(find_resp.mac_addr == cr_resp.mac_addr);

    Ok(())
}
