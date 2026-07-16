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
    segment_id: &str,
    hostname: Option<&str>,
    phone_home_enable: bool,
    wait_until_ready: bool,
    keyset_ids: &[&str],
) -> eyre::Result<String> {
    tracing::info!(
        host_machine_id = %host_machine_id,
        network_segment_id = segment_id,
        "Creating instance",
    );

    let network = serde_json::json!({
        "interfaces": [{
            "function_type": "PHYSICAL",
            "network_segment_id": {"value": segment_id}
        }]
    });

    create_with_network(
        addrs,
        host_machine_id,
        network,
        hostname,
        phone_home_enable,
        wait_until_ready,
        keyset_ids,
    )
    .await
}

/// Creates an instance whose HostInband interfaces are resolved automatically
/// within the requested Flat VPC.
pub async fn create_with_auto_host_inband_networking(
    addrs: &[SocketAddr],
    host_machine_id: &MachineId,
    flat_vpc_id: &str,
) -> eyre::Result<String> {
    tracing::info!(
        host_machine_id = %host_machine_id,
        flat_vpc_id,
        "Creating automatically-networked instance",
    );

    let network = serde_json::json!({
        "interfaces": [],
        "auto": true,
        "auto_config": {
            "vpc_id": {"value": flat_vpc_id}
        }
    });

    create_with_network(addrs, host_machine_id, network, None, false, false, &[]).await
}

async fn create_with_network(
    addrs: &[SocketAddr],
    host_machine_id: &MachineId,
    network: serde_json::Value,
    hostname: Option<&str>,
    phone_home_enable: bool,
    wait_until_ready: bool,
    keyset_ids: &[&str],
) -> eyre::Result<String> {
    let mut tenant = serde_json::json!({
        "tenant_organization_id": "tenant_organization",
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

    let instance_config = serde_json::json!({
        "tenant": tenant,
        "network": network,
        "os": os,
    });

    let data = serde_json::json!({
        "machine_id": {"id": host_machine_id},
        "config": instance_config,
        "metadata": {
             "name": "test_instance",
             "description": "tests/integration/instance"
        },
    });
    let instance_id = grpcurl_id(addrs, "AllocateInstance", &data.to_string()).await?;
    tracing::info!(
        instance_id = %instance_id,
        "Instance created",
    );

    if !wait_until_ready {
        return Ok(instance_id);
    }

    wait_for_state(addrs, host_machine_id, "Assigned/Ready").await?;

    if phone_home_enable {
        wait_for_instance_state(addrs, &instance_id, "PROVISIONING").await?;
        let before_phone = get_instance_state(addrs, &instance_id).await?;
        assert_eq!(before_phone, "PROVISIONING");
        // Phone home to transition to the ready state
        phone_home(addrs, &instance_id, host_machine_id).await?;
        wait_for_instance_state(addrs, &instance_id, "READY").await?;
        let after_phone = get_instance_state(addrs, &instance_id).await?;
        assert_eq!(after_phone, "READY");
    }

    // These 2 states should be equivalent
    wait_for_instance_state(addrs, &instance_id, "READY").await?;
    wait_for_state(addrs, host_machine_id, "Assigned/Ready").await?;

    tracing::info!(
        instance_id = %instance_id,
        "Instance is ready",
    );

    Ok(instance_id)
}

/// Allocates an instance with dual-stack VPC prefixes.
/// Takes a primary (v4) VPC prefix ID and an optional v6 VPC prefix ID.
pub async fn create_with_vpc_prefixes(
    addrs: &[SocketAddr],
    host_machine_id: &MachineId,
    vpc_prefix_ids: &[&str],
) -> eyre::Result<String> {
    tracing::info!(
        %host_machine_id,
        ?vpc_prefix_ids,
        "Creating instance",
    );

    let v4_id = vpc_prefix_ids
        .first()
        .ok_or_else(|| eyre::eyre!("at least one VPC prefix ID required"))?;

    let mut iface = serde_json::json!({
        "function_type": "PHYSICAL",
        "vpc_prefix_id": {"value": v4_id},
    });

    if let Some(v6_id) = vpc_prefix_ids.get(1) {
        iface["ipv6_interface_config"] = serde_json::json!({"vpc_prefix_id": {"value": v6_id}});
    }

    let data = serde_json::json!({
        "machine_id": {"id": host_machine_id},
        "config": {
            "tenant": {
                "tenant_organization_id": "MyOrg",
            },
            "network": {
                "interfaces": [iface]
            },
            "os": {
                "ipxe": {
                    "ipxe_script": "chain --autofree https://boot.netboot.xyz"
                },
                "phone_home_enabled": false,
                "user_data": "hello",
            },
        },
        "metadata": {
             "name": "test_instance_dual_stack",
             "description": "tests/integration/dual_stack_instance"
        },
    });

    let instance_id = grpcurl_id(addrs, "AllocateInstance", &data.to_string()).await?;
    tracing::info!(
        instance_id = %instance_id,
        ?vpc_prefix_ids,
        "Instance created",
    );
    Ok(instance_id)
}

pub async fn release(
    addrs: &[SocketAddr],
    host_machine_id: &MachineId,
    instance_id: &str,
    wait_until_ready: bool,
) -> eyre::Result<()> {
    tracing::info!(
        instance_id,
        host_machine_id = %host_machine_id,
        "Releasing instance",
    );

    let data = serde_json::json!({
        "id": {"value": instance_id}
    });
    let resp = grpcurl(addrs, "ReleaseInstance", Some(data)).await?;
    tracing::info!(
        release_instance_response = %resp,
        "ReleaseInstance response",
    );

    if !wait_until_ready {
        return Ok(());
    }

    wait_for_instance_state(addrs, instance_id, "TERMINATING").await?;
    wait_for_state(addrs, host_machine_id, "Assigned/BootingWithDiscoveryImage").await?;

    let data = serde_json::json!({
        "instance_ids": [{"value": instance_id}]
    });
    let response = grpcurl(addrs, "FindInstancesByIds", Some(&data)).await?;
    let resp: serde_json::Value = serde_json::from_str(&response)?;
    let ip_address = resp["instances"]
        .as_array()
        .and_then(|instances| instances.first())
        .and_then(|instance| instance["status"]["network"]["interfaces"].as_array())
        .and_then(|interfaces| {
            interfaces.iter().find_map(|interface| {
                interface["addresses"]
                    .as_array()
                    .and_then(|addresses| addresses.iter().find_map(|address| address.as_str()))
            })
        });
    if let Some(ip_address) = ip_address {
        tracing::info!(instance_id, ip_address, "Instance is terminating",);
    } else {
        tracing::info!(instance_id, "Instance is terminating",);
    }

    wait_for_state(addrs, host_machine_id, "WaitingForCleanup/HostCleanup").await?;
    let data = serde_json::json!({
        "instance_ids": [{"value": instance_id}]
    });
    let response = grpcurl(addrs, "FindInstancesByIds", Some(&data)).await?;
    let resp: serde_json::Value = serde_json::from_str(&response)?;
    tracing::info!(
        find_instances_response = %resp,
        "FindInstancesByIds Response",
    );
    assert!(resp["instances"].as_array().unwrap().is_empty());

    tracing::info!(instance_id, "Instance is released",);

    Ok(())
}

pub async fn phone_home(
    addrs: &[SocketAddr],
    instance_id: &str,
    host_machine_id: &MachineId,
) -> eyre::Result<()> {
    let data = serde_json::json!({
        "instance_id": {"value": instance_id},
    });

    tracing::info!(
        %host_machine_id,
        instance_id,
        "Phoning home",
    );

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
    tracing::info!(
        instance_state = %state,
        "Current instance state",
    );

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

pub async fn get_instance_json_by_id(
    addrs: &[SocketAddr],
    instance_id: &str,
) -> eyre::Result<serde_json::Value> {
    let data = serde_json::json!({
        "instance_ids": [{"value": instance_id}]
    });
    let response = grpcurl(addrs, "FindInstancesByIds", Some(&data)).await?;
    let response: serde_json::Value = serde_json::from_str(&response)?;
    response["instances"]
        .as_array()
        .and_then(|instances| instances.first())
        .cloned()
        .ok_or_else(|| eyre::eyre!("instance {instance_id} was not returned by FindInstancesByIds"))
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

    tracing::info!(instance_id, target_state, "Waiting for Instance state",);
    while start.elapsed() < MAX_WAIT {
        latest_state = get_instance_state(addrs, instance_id).await?;

        if latest_state.contains(target_state) {
            return Ok(());
        }
        tracing::info!(
            instance_state = %latest_state,
            "Current instance state",
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    eyre::bail!(
        "even after {MAX_WAIT:?} time, {instance_id} did not reach state {target_state}\n
        latest state: {latest_state}"
    );
}
