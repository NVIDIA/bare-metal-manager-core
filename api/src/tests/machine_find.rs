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
use data_encoding::BASE32_DNSSEC;
use std::net::IpAddr;

use crate::model::hardware_info::HardwareInfo;
use crate::tests::sku::tests::FULL_SKU_DATA;
use crate::{
    db,
    db::{ObjectFilter, machine::MachineSearchConfig},
    model::machine::machine_id::{host_id_from_dpu_hardware_info, try_parse_machine_id},
};
use forge_uuid::machine::{MACHINE_ID_PREFIX_LENGTH, MachineId};
use itertools::Itertools;
use mac_address::MacAddress;
use sha2::{Digest, Sha256};
use tonic::Request;

use crate::tests::common;
use crate::tests::common::api_fixtures::create_managed_host_multi_dpu;
use common::{
    api_fixtures::{
        create_managed_host, create_test_env, dpu::create_dpu_machine,
        managed_host::ManagedHostConfig, site_explorer,
    },
    mac_address_pool::DPU_OOB_MAC_ADDRESS_POOL,
};
use rpc::forge::{
    AssociateMachinesWithInstanceTypeRequest, FindInstanceTypeIdsRequest, MachinesByIdsRequest,
    forge_server::Forge,
};

#[crate::sqlx_test]
async fn test_find_machine_by_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let mut txn = env.pool.begin().await.unwrap();

    let machine = db::machine::find_by_query(&mut txn, &dpu_machine_id.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert_eq!(machine.id, dpu_machine_id);
    assert!(machine.is_dpu());

    // We shouldn't find a machine that doesn't exist
    let mut new_id = dpu_machine_id.to_string();
    match unsafe { new_id.as_bytes_mut().get_mut(MACHINE_ID_PREFIX_LENGTH + 1) } {
        Some(c) if *c == b'a' => *c = b'b',
        Some(c) => *c = b'a',
        None => panic!("Not expected"),
    }
    let id2: MachineId = new_id.parse().unwrap();
    assert!(
        db::machine::find_by_query(&mut txn, &id2.to_string())
            .await
            .unwrap()
            .is_none()
    );
}

#[crate::sqlx_test]
async fn test_find_machine_by_ip(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine =
        db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();
    let ip = &dpu_machine.interfaces[0].addresses[0];

    let machine = db::machine::find_by_query(&mut txn, &ip.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert_eq!(machine.id, dpu_machine_id);
    assert_eq!(&machine.interfaces[0].addresses[0], ip);

    // We shouldn't find a machine that doesn't exist
    let ip2: IpAddr = "254.254.254.254".parse().unwrap();
    assert!(
        db::machine::find_by_query(&mut txn, &ip2.to_string())
            .await
            .unwrap()
            .is_none()
    );
}

#[crate::sqlx_test]
async fn test_find_machine_without_sku(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host(&env).await.0;
    let mut txn = env.pool.begin().await.unwrap();

    let machine = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(machine.hw_sku, None);
}

#[crate::sqlx_test]
async fn test_find_machine_with_sku(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host(&env).await.0;
    let sku = serde_json::de::from_str::<rpc::forge::Sku>(FULL_SKU_DATA)
        .unwrap()
        .into();

    let mut txn = env.pool.begin().await.unwrap();
    db::sku::create(&mut txn, &sku).await.unwrap();
    db::machine::assign_sku(&mut txn, &host_machine_id, "sku id")
        .await
        .unwrap();

    txn.commit().await.unwrap();
    let mut txn = env.pool.begin().await.unwrap();

    let machine = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(machine.hw_sku, Some("sku id".to_string()));
}

#[crate::sqlx_test]
async fn test_find_machine_by_mac(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine = db::machine::find_one(
        &mut txn,
        &dpu_machine_id,
        MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    let mac = &dpu_machine.interfaces[0].mac_address;

    let machine = db::machine::find_by_query(&mut txn, &mac.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert_eq!(machine.id, dpu_machine_id);
    assert_eq!(&machine.interfaces[0].mac_address, mac);
    assert!(DPU_OOB_MAC_ADDRESS_POOL.contains(machine.interfaces[0].mac_address));

    // We shouldn't find a machine that doesn't exist
    let mut mac2 = mac.bytes();
    // Previously just set to 0xFF, but that could be the actual value
    mac2[5] ^= 0xFF;
    let mac2 = MacAddress::from(mac2);
    assert!(
        db::machine::find_by_query(&mut txn, &mac2.to_string())
            .await
            .unwrap()
            .is_none()
    );
}

#[crate::sqlx_test]
async fn test_find_machine_by_hostname(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine = db::machine::find_one(
        &mut txn,
        &dpu_machine_id,
        MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    let hostname = &dpu_machine.interfaces[0].hostname.clone();

    let machine = db::machine::find_by_query(&mut txn, hostname)
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert_eq!(machine.id, dpu_machine_id);
    assert_eq!(&machine.interfaces[0].hostname, hostname);

    // We shouldn't find a machine that doesn't exist
    let hostname2 = format!("a{}", hostname);
    assert!(
        db::machine::find_by_query(&mut txn, &hostname2)
            .await
            .unwrap()
            .is_none()
    );
}

#[crate::sqlx_test]
async fn test_find_machine_by_fqdn(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine =
        db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

    let fqdn = format!("{}.dwrt1.com", &dpu_machine.interfaces[0].hostname);

    let mut machines = env
        .api
        .find_machines(Request::new(rpc::forge::MachineSearchQuery {
            id: None,
            fqdn: Some(fqdn.clone()),
            search_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines;
    let machine = machines.remove(0);
    assert!(machines.is_empty());
    assert_eq!(
        machine.id.clone().unwrap().to_string(),
        dpu_machine_id.to_string()
    );

    // We shouldn't find a machine that doesn't exist
    let fqdn2 = format!("a{}", fqdn);
    let machines = env
        .api
        .find_machines(Request::new(rpc::forge::MachineSearchQuery {
            id: None,
            fqdn: Some(fqdn2),
            search_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines;
    assert!(machines.is_empty());
}

#[crate::sqlx_test]
async fn test_find_machine_dpu_included(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let machines = env.find_machines(None, None, true).await;
    assert_eq!(machines.machines.len(), 2); // 1 host and 1 DPU

    let machine_types = machines
        .machines
        .into_iter()
        .map(|x| x.machine_type)
        .collect_vec();

    assert!(machine_types.contains(&(rpc::forge::MachineType::Host as i32)));
    assert!(machine_types.contains(&(rpc::forge::MachineType::Dpu as i32)));
}

#[crate::sqlx_test]
async fn test_find_machine_dpu_excluded(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let machines = env.find_machines(None, None, false).await;
    assert_eq!(machines.machines.len(), 1); // 1 host
    assert_eq!(
        machines.machines[0].machine_type,
        rpc::forge::MachineType::Host as i32
    );
}

#[crate::sqlx_test]
async fn test_find_all_machines_when_there_arent_any(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Could create a transaction on database pool");

    let machines = db::machine::find(
        &mut txn,
        ObjectFilter::All,
        crate::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(machines.is_empty());
}

#[crate::sqlx_test]
async fn test_find_machine_ids(pool: sqlx::PgPool) {
    let config = crate::db::machine::MachineSearchConfig {
        include_dpus: true,
        include_predicted_host: true,
        ..Default::default()
    };

    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let host_machine_id = host_id_from_dpu_hardware_info(&HardwareInfo::from(
        host_sim.config.get_and_assert_single_dpu(),
    ))
    .unwrap();
    let mut txn = env.pool.begin().await.unwrap();

    let machine_ids = db::machine::find_machine_ids(&mut txn, config)
        .await
        .unwrap();

    assert_eq!(machine_ids.len(), 2);
    assert!(machine_ids.contains(&dpu_machine_id));
    assert!(machine_ids.contains(&host_machine_id));

    // Create a managed host
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    // Find an existing instance type in the test env
    let instance_type_id = env
        .api
        .find_instance_type_ids(tonic::Request::new(FindInstanceTypeIdsRequest {}))
        .await
        .unwrap()
        .into_inner()
        .instance_type_ids
        .first()
        .unwrap()
        .to_owned();

    // Associate the machine with the instance type
    let _ = env
        .api
        .associate_machines_with_instance_type(tonic::Request::new(
            AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host_machine_id.to_string()],
            },
        ))
        .await
        .unwrap();

    // Create a config to test searching by instance type id
    let config = crate::db::machine::MachineSearchConfig {
        instance_type_id: Some(instance_type_id.parse().unwrap()),
        ..Default::default()
    };

    // Try to find machines for the instance type.
    let machine_ids = db::machine::find_machine_ids(&mut txn, config)
        .await
        .unwrap();

    assert_eq!(machine_ids.len(), 1);
    assert_eq!(machine_ids[0], host_machine_id);
}

#[crate::sqlx_test]
async fn test_find_dpu_machine_ids(pool: sqlx::PgPool) {
    let config = crate::db::machine::MachineSearchConfig {
        include_dpus: true,
        exclude_hosts: true,
        ..Default::default()
    };

    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let host_machine_id = host_id_from_dpu_hardware_info(&HardwareInfo::from(
        host_sim.config.get_and_assert_single_dpu(),
    ))
    .unwrap();
    let mut txn = env.pool.begin().await.unwrap();

    let machine_ids = db::machine::find_machine_ids(&mut txn, config)
        .await
        .unwrap();

    assert_eq!(machine_ids.len(), 1);
    assert!(machine_ids.contains(&dpu_machine_id));
    assert!(!machine_ids.contains(&host_machine_id));
}

#[crate::sqlx_test]
async fn test_find_predicted_host_machine_ids(pool: sqlx::PgPool) {
    let config = crate::db::machine::MachineSearchConfig {
        include_predicted_host: true,
        ..Default::default()
    };

    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let host_machine_id = host_id_from_dpu_hardware_info(&HardwareInfo::from(
        host_sim.config.get_and_assert_single_dpu(),
    ))
    .unwrap();
    let mut txn = env.pool.begin().await.unwrap();

    let machine_ids = db::machine::find_machine_ids(&mut txn, config)
        .await
        .unwrap();

    assert_eq!(machine_ids.len(), 1);
    assert!(!machine_ids.contains(&dpu_machine_id));
    assert!(machine_ids.contains(&host_machine_id));
}

#[crate::sqlx_test]
async fn test_find_host_machine_ids_when_predicted(pool: sqlx::PgPool) {
    let config = crate::db::machine::MachineSearchConfig::default();

    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let _dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let mut txn = env.pool.begin().await.unwrap();

    let machine_ids = db::machine::find_machine_ids(&mut txn, config)
        .await
        .unwrap();

    assert!(machine_ids.is_empty());
}

#[crate::sqlx_test]
async fn test_find_host_machine_ids(pool: sqlx::PgPool) {
    let config = crate::db::machine::MachineSearchConfig::default();

    let env = create_test_env(pool).await;
    let (host_machine_id, _) = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await.unwrap();

    tracing::info!("finding machine ids");
    let machine_ids = db::machine::find_machine_ids(&mut txn, config)
        .await
        .unwrap();
    assert_eq!(machine_ids.len(), 1);
    assert!(machine_ids.contains(&host_machine_id));
}

#[crate::sqlx_test]
async fn test_find_mixed_host_machine_ids(pool: sqlx::PgPool) {
    let config = crate::db::machine::MachineSearchConfig {
        include_predicted_host: true,
        ..Default::default()
    };

    let env = create_test_env(pool).await;
    let (host_machine_id, _) = create_managed_host(&env).await;

    let host_sim2 = env.start_managed_host_sim();
    create_dpu_machine(&env, &host_sim2.config).await;
    let predicted_host_machine_id = host_id_from_dpu_hardware_info(&HardwareInfo::from(
        host_sim2.config.get_and_assert_single_dpu(),
    ))
    .unwrap();

    let mut txn = env.pool.begin().await.unwrap();

    tracing::info!("finding machine ids");
    let machine_ids = db::machine::find_machine_ids(&mut txn, config)
        .await
        .unwrap();
    assert_eq!(machine_ids.len(), 2);
    assert!(machine_ids.contains(&host_machine_id));
    assert!(machine_ids.contains(&predicted_host_machine_id));
}

#[crate::sqlx_test]
async fn test_attached_dpu_machine_ids_multi_dpu(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (machine_id, _) = create_managed_host_multi_dpu(&env, 2).await;

    // Now host1 should have two DPUs.
    let host_machine = env
        .api
        .find_machines_by_ids(tonic::Request::new(MachinesByIdsRequest {
            machine_ids: vec![machine_id.into()],
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);
    let dpu_ids = host_machine.associated_dpu_machine_ids;
    assert_eq!(
        dpu_ids.len(),
        2,
        "host machine should have had 2 DPU IDs, got {}",
        dpu_ids.len()
    );

    for ref dpu_id in dpu_ids.iter() {
        assert!(
            dpu_ids.contains(dpu_id),
            "host machine has an unexpected associated_dpu_machine_id {}",
            dpu_id
        );
    }

    let deprecated_dpu_id = host_machine.associated_dpu_machine_id
        .expect("host machine should fill in an associated_dpu_machine_id field for backwards compatibility");

    let first_dpu_id = dpu_ids.into_iter().next().unwrap();
    assert_eq!(
        deprecated_dpu_id, first_dpu_id,
        "deprecated DPU field should equal the first DPU ID"
    );
}

#[crate::sqlx_test()]
async fn test_find_machines_by_ids_over_max(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // create vector of machine IDs with more than max allowed
    // it does not matter if these are real or not, since we are testing an error back for passing more than max
    let end_index: u32 = env.config.max_find_by_ids + 1;
    let machine_ids = (1..=end_index)
        .map(|index| {
            let serial = format!("machine_{index}");
            let hash: [u8; 32] = Sha256::new_with_prefix(serial.as_bytes()).finalize().into();
            let encoded = BASE32_DNSSEC.encode(&hash);
            ::rpc::common::MachineId {
                id: format!("fm100ds{encoded}"),
            }
        })
        .collect();
    //build request
    let request: Request<MachinesByIdsRequest> = Request::new(MachinesByIdsRequest {
        machine_ids,
        ..Default::default()
    });
    // execute
    let response = env.api.find_machines_by_ids(request).await;
    // validate
    assert!(
        response.is_err(),
        "expected an error when passing more than allowed number of machine IDs"
    );
    assert_eq!(
        response.err().unwrap().message(),
        format!(
            "no more than {} IDs can be accepted",
            env.config.max_find_by_ids
        )
    );
}

#[crate::sqlx_test()]
async fn test_find_machines_by_ids_none(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    let request = tonic::Request::new(::rpc::forge::MachinesByIdsRequest::default());

    let response = env.api.find_machines_by_ids(request).await;
    // validate
    assert!(
        response.is_err(),
        "expected an error when passing no machine IDs"
    );
    assert_eq!(
        response.err().unwrap().message(),
        "at least one ID must be provided",
    );
}

#[crate::sqlx_test]
async fn test_machine_capabilities_response(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Create a new managed host in the DB and get the snapshot.
    let mh = site_explorer::new_host(&env, ManagedHostConfig::default())
        .await
        .unwrap();

    // Convert the caps of the Machine to the proto representation
    // for later comparison.
    let mut caps = mh.host_snapshot.to_capabilities().unwrap();

    // Make sure we have at least _something_ in the capabilities.
    // CPU should be a safe one to rely on.  If we don't have CPUs,
    // we've got bad test data.
    assert!(!caps.cpu.is_empty());

    caps.sort();
    let caps_from_machine = rpc::protos::forge::MachineCapabilitiesSet::from(caps);

    // Find the new host through the API
    let machine = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            include_history: false,
            machine_ids: vec![mh.host_snapshot.id.to_string().into()],
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .pop()
        .unwrap();

    let caps_from_rpc_call = machine.capabilities.unwrap();

    // Check the gRPC response and the original machine agree
    assert_eq!(caps_from_rpc_call, caps_from_machine);

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_machine_by_instance_type(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Find the existing instance types in the test env
    let existing_instance_type_ids = env
        .api
        .find_instance_type_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypeIdsRequest {},
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_type_ids;

    let existing_instance_types = env
        .api
        .find_instance_types_by_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypesByIdsRequest {
                instance_type_ids: existing_instance_type_ids,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_types;

    // Our known fixture instance type
    let instance_type_id = existing_instance_types[0].id.clone();

    let (tmp_machine_id, _) = create_managed_host(&env).await;

    // Find the new host through the API
    let machines = env
        .api
        .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
            instance_type_id: Some(instance_type_id.clone()),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machine_ids;

    // We should find nothing because we haven't associated our machine with
    // an instance type
    assert!(machines.is_empty());

    // Associate the machine with the instance type
    let _ = env
        .api
        .associate_machines_with_instance_type(tonic::Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![tmp_machine_id.to_string()],
            },
        ))
        .await
        .unwrap();

    // Find the new host through the API
    let machines = env
        .api
        .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
            instance_type_id: Some(instance_type_id),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machine_ids;

    // We should now find our machine
    assert_eq!(machines.len(), 1);

    // Confirm that what we found is the right
    // machine
    assert_eq!(machines[0].id, tmp_machine_id.to_string());

    Ok(())
}
