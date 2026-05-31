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
use rpc::forge_agent_control_response::{self as fac, Action};

use crate::handlers::dpa::process_scout_req;
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
        device_description: Some("NVIDIA BlueField-3 B3140L E-Series FHHL SuperNIC; 400GbE / NDR IB (default mode); Single-port QSFP112
; PCIe Gen5.0 x16; 8 Arm cores; 16GB on-board DDR; integrated BMC; Crypto Enabled".to_string()),
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

#[crate::sqlx_test]
async fn dpa_scout_request_returns_typed_mlx_action(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;

    let cr_resp = env
        .api
        .create_dpa_interface(tonic::Request::new(DpaInterfaceCreationRequest {
            mac_addr: "00:11:22:33:44:55".to_string(),
            machine_id: Some(mh.id),
            device_type: "BlueField3".to_string(),
            pci_name: "0000:cc:00.0".to_string(),
            device_description: Some("NVIDIA BlueField-3 B3140L E-Series FHHL SuperNIC; 400GbE / NDR IB (default mode); Single-port QSFP112".to_string()),
        }))
        .await
        .unwrap()
        .into_inner();

    let dpa_id = cr_resp.id.unwrap();
    let dpa = db::dpa_interface::find_by_ids(&env.pool, &[dpa_id], false)
        .await?
        .pop()
        .expect("created dpa interface");
    let mut txn = env.pool.begin().await.unwrap();
    db::dpa_interface::try_update_controller_state(
        &mut txn,
        dpa.id,
        dpa.controller_state.version,
        dpa.controller_state.version.increment(),
        &model::dpa_interface::DpaInterfaceControllerState::ApplyFirmware,
    )
    .await?;
    txn.commit().await.unwrap();

    let action = process_scout_req(&env.api, mh.id).await?;
    let Action::MlxAction(mlx_action) = action else {
        panic!("expected typed mlx action");
    };
    let device_action = mlx_action
        .device_actions
        .into_iter()
        .next()
        .expect("device action");

    assert_eq!(device_action.pci_name, "0000:cc:00.0");
    assert!(matches!(
        device_action.command,
        Some(fac::mlx_device_action::Command::ApplyFirmware(
            fac::MlxDeviceApplyFirmware { profile: None }
        ))
    ));

    Ok(())
}
