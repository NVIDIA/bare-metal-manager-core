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

use std::net::SocketAddr;

use carbide_uuid::machine::MachineId;

use super::grpcurl::{grpcurl, grpcurl_id};
use super::machine::wait_for_state;

pub async fn create(
    addrs: &[SocketAddr],
    host_machine_id: &MachineId,
    segment_id: Option<&str>,
    hostname: Option<&str>,
    phone_home_enable: bool,
    wait_until_ready: bool,
    keyset_ids: &[&str],
) -> eyre::Result<String> {
    tracing::info!(
        "Creating instance with machine: {host_machine_id}, with network segment: {}",
        segment_id.unwrap_or("<none>")
    );

    let mut tenant = serde_json::json!({
        "tenant_organization_id": "MyOrg",
        "tenantKeysetIds": keyset_ids,
    });

    if let Some(hostname) = hostname {
        tenant
            .as_object_mut()
            .unwrap()
            .insert("hostname".to_string(), serde_json::json!(hostname));
    }

    let os = serde_json::json!({
        "ipxe": {
            "ipxe_script": "chain --autofree https://boot.netboot.xyz"
        },
        "phone_home_enabled": phone_home_enable,
        "user_data": "hello",
    });

    let instance_config = match segment_id {
        Some(segment_id) => serde_json::json!({
            "tenant": tenant,
            "network": {
                "interfaces": [{
                    "function_type": "PHYSICAL",
                    "network_segment_id": {"value": segment_id}
                }]
            },
            "os": os,
        }),
        // omit network from config if we're not specifying a segment
        None => serde_json::json!({
            "tenant": tenant,
        }),
    };

    let data = serde_json::json!({
        "machine_id": {"id": host_machine_id},
        "config": instance_config,
        "metadata": {
             "name": "test_instance",
             "description": "tests/integration/instance"
        },
    });
    let instance_id = grpcurl_id(addrs, "AllocateInstance", &data.to_string()).await?;
    tracing::info!("Instance created with ID {instance_id}");

    if !wait_until_ready {
        return Ok(instance_id);
    }

    wait_for_state(addrs, host_machine_id, "Assigned/Ready").await?;

    if phone_home_enable {
        wait_for_instance_state(addrs, &instance_id, "PROVISIONING").await?;
        let before_phone = get_instance_state(addrs, &instance_id).await?;
        assert_eq!(before_phone, "PROVISIONING");
        // Phone home to transition to the ready state
        phone_home(addrs, &instance_id).await?;
        wait_for_instance_state(addrs, &instance_id, "READY").await?;
        let after_phone = get_instance_state(addrs, &instance_id).await?;
        assert_eq!(after_phone, "READY");
    }

    // These 2 states should be equivalent
    wait_for_instance_state(addrs, &instance_id, "READY").await?;
    wait_for_state(addrs, host_machine_id, "Assigned/Ready").await?;

    tracing::info!("Instance with ID {instance_id} is ready");

    Ok(instance_id)
}

pub async fn release(
    addrs: &[SocketAddr],
    host_machine_id: &MachineId,
    instance_id: &str,
    wait_until_ready: bool,
) -> eyre::Result<()> {
    let data = serde_json::json!({
        "machine_ids": [{"id": host_machine_id}],
    });
    let resp = grpcurl(addrs, "FindMachinesByIds", Some(data)).await?;
    let response: serde_json::Value = serde_json::from_str(&resp)?;
    let machine_json = &response["machines"][0];
    let ip_address = machine_json["interfaces"][0]["address"][0]
        .as_str()
        .unwrap()
        .to_string();

    tracing::info!("Releasing instance {instance_id} on machine: {host_machine_id}");

    let data = serde_json::json!({
        "id": {"value": instance_id}
    });
    let resp = grpcurl(addrs, "ReleaseInstance", Some(data)).await?;
    tracing::info!("ReleaseInstance response: {}", resp);

    if !wait_until_ready {
        return Ok(());
    }

    wait_for_instance_state(addrs, instance_id, "TERMINATING").await?;
    wait_for_state(addrs, host_machine_id, "Assigned/BootingWithDiscoveryImage").await?;

    tracing::info!("Instance with ID {instance_id} at {ip_address} is terminating");

    wait_for_state(addrs, host_machine_id, "WaitingForCleanup/HostCleanup").await?;
    let data = serde_json::json!({
        "instance_ids": [{"value": instance_id}]
    });
    let response = grpcurl(addrs, "FindInstancesByIds", Some(&data)).await?;
    let resp: serde_json::Value = serde_json::from_str(&response)?;
    tracing::info!("FindInstancesByIds Response: {}", resp);
    assert!(resp["instances"].as_array().unwrap().is_empty());

    tracing::info!("Instance with ID {instance_id} is released");

    Ok(())
}

pub async fn phone_home(addrs: &[SocketAddr], instance_id: &str) -> eyre::Result<()> {
    let data = serde_json::json!({
        "instance_id": {"value": instance_id},
    });

    tracing::info!("Phoning home with data: {data}");

    grpcurl(addrs, "UpdateInstancePhoneHomeLastContact", Some(&data)).await?;

    Ok(())
}

pub async fn get_instance_state(addrs: &[SocketAddr], instance_id: &str) -> eyre::Result<String> {
    let data = serde_json::json!({
        "instance_ids": [{"value": instance_id}]
    });

    let response = grpcurl(addrs, "FindInstancesByIds", Some(&data)).await?;
    let resp: serde_json::Value = serde_json::from_str(&response)?;
    let state = resp["instances"][0]["status"]["tenant"]["state"]
        .as_str()
        .unwrap()
        .to_string();
    tracing::info!("\tCurrent instance state: {state}");

    Ok(state)
}

pub async fn get_instance_json_by_machine_id(
    addrs: &[SocketAddr],
    machine_id: &str,
) -> eyre::Result<serde_json::Value> {
    let data = serde_json::json!({ "id": machine_id });
    let response = grpcurl(addrs, "FindInstanceByMachineID", Some(&data)).await?;
    Ok(serde_json::from_str(&response)?)
}

/// Waits for an instance to reach a certain state
pub async fn wait_for_instance_state(
    addrs: &[SocketAddr],
    instance_id: &str,
    target_state: &str,
) -> eyre::Result<()> {
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();

    let mut latest_state = String::new();

    tracing::info!("Waiting for Instance {instance_id} state {target_state}");
    while start.elapsed() < MAX_WAIT {
        latest_state = get_instance_state(addrs, instance_id).await?;

        if latest_state.contains(target_state) {
            return Ok(());
        }
        tracing::info!("\tCurrent instance state: {latest_state}");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    eyre::bail!(
        "Even after {MAX_WAIT:?} time, {instance_id} did not reach state {target_state}\n
        Latest state: {latest_state}"
    );
}
