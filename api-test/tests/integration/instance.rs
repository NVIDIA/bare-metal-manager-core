/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::net::SocketAddr;

use super::{
    grpcurl::{grpcurl, grpcurl_id},
    host::discover_machine,
    machine::wait_for_state,
};

pub fn create(
    addr: SocketAddr,
    host_machine_id: &str,
    segment_id: &str,
    phone_home_enable: bool,
) -> eyre::Result<String> {
    tracing::info!(
        "Creating instance with machine: {host_machine_id}, with network segment: {segment_id}"
    );

    let data = serde_json::json!({
        "machine_id": {"id": host_machine_id},
        "config": {
            "tenant": {
                "tenant_organization_id": "MyOrg",
                "user_data": "hello",
                "custom_ipxe": "chain --autofree https://boot.netboot.xyz",
                "phone_home_enabled": phone_home_enable,

            },
            "network": {
                "interfaces": [{
                    "function_type": "PHYSICAL",
                    "network_segment_id": {"value": segment_id}
                }]
            }
        },
        "metadata": {
             "name": "test_instance",
             "description": "tests/integration/instance"
        }
    });
    let instance_id = grpcurl_id(addr, "AllocateInstance", &data.to_string())?;
    tracing::info!("Instance created with ID {instance_id}");

    wait_for_state(addr, host_machine_id, "Assigned/WaitingForNetworkConfig")?;

    if phone_home_enable {
        wait_for_instance_state(addr, &instance_id, "PROVISIONING")?;
        let before_phone = get_instance_state(addr, &instance_id)?;
        assert_eq!(before_phone, "PROVISIONING");
        // Phone home to transition to the ready state
        phone_home(addr, &instance_id)?;
        wait_for_instance_state(addr, &instance_id, "READY")?;
        let after_phone = get_instance_state(addr, &instance_id)?;
        assert_eq!(after_phone, "READY");
    }

    // These 2 states should be equivalent
    wait_for_instance_state(addr, &instance_id, "READY")?;
    wait_for_state(addr, host_machine_id, "Assigned/Ready")?;

    tracing::info!("Instance with ID {instance_id} is ready");

    Ok(instance_id)
}

pub fn release(addr: SocketAddr, host_machine_id: &str, instance_id: &str) -> eyre::Result<()> {
    let data = serde_json::json!({
        "id": {"id": host_machine_id},
        "search_config": {"include_dpus": false}
    });
    let resp = grpcurl(addr, "FindMachines", Some(data))?;
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
    let resp = grpcurl(addr, "ReleaseInstance", Some(data))?;
    tracing::info!("ReleaseInstance response: {}", resp);

    wait_for_instance_state(addr, instance_id, "TERMINATING")?;
    wait_for_state(addr, host_machine_id, "Assigned/BootingWithDiscoveryImage")?;

    tracing::info!("Instance with ID {instance_id} at {ip_address} is terminating");
    discover_machine(addr, &ip_address)?;

    wait_for_state(addr, host_machine_id, "WaitingForCleanup/HostCleanup")?;
    let data = serde_json::json!({
        "id": {"value": instance_id}
    });
    let response = grpcurl(addr, "FindInstances", Some(&data))?;
    let resp: serde_json::Value = serde_json::from_str(&response)?;
    tracing::info!("FindInstances Response: {}", resp);
    assert!(resp["instances"].as_array().unwrap().is_empty());

    tracing::info!("Instance with ID {instance_id} is released");

    Ok(())
}

pub fn phone_home(addr: SocketAddr, instance_id: &str) -> eyre::Result<()> {
    let data = serde_json::json!({
        "instance_id": {"value": instance_id},
    });

    tracing::info!("Phoning home with data: {data}");

    grpcurl(addr, "UpdateInstancePhoneHomeLastContact", Some(&data))?;

    Ok(())
}

pub fn get_instance_state(addr: SocketAddr, instance_id: &str) -> eyre::Result<String> {
    let data = serde_json::json!({
        "id": {"value": instance_id}
    });

    let response = grpcurl(addr, "FindInstances", Some(&data))?;
    let resp: serde_json::Value = serde_json::from_str(&response)?;
    let state = resp["instances"][0]["status"]["tenant"]["state"]
        .as_str()
        .unwrap()
        .to_string();
    tracing::info!("\tCurrent instance state: {state}");

    Ok(state)
}

/// Waits for an instance to reach a certain state
pub fn wait_for_instance_state(
    addr: SocketAddr,
    instance_id: &str,
    target_state: &str,
) -> eyre::Result<()> {
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();

    let mut latest_state = String::new();

    tracing::info!("Waiting for Instance {instance_id} state {target_state}");
    while start.elapsed() < MAX_WAIT {
        latest_state = get_instance_state(addr, instance_id)?;

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
