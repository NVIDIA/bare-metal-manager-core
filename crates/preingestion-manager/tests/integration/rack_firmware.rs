// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use api_test_helper::mock_rms::MockRmsApi;
use async_trait::async_trait;
use carbide_preingestion_manager::{PreingestionManager, RackFirmwareDependencies};
use carbide_rack::firmware_object::FirmwareObjectFetcher;
use carbide_redfish::libredfish::test_support::RedfishSim;
use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialWriter, Credentials,
};
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::default_config;
use carbide_uuid::rack::{RackId, RackProfileId};
use component_manager::component_manager::ComponentManager;
use component_manager::mock::MockPowerShelfManager;
use component_manager::rms::RmsBackend;
use librms::protos::rack_manager as rms;
use mac_address::MacAddress;
use model::allocation_type::AllocationType;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use model::expected_rack::ExpectedRack;
use model::expected_switch::ExpectedSwitch;
use model::rack::RackConfig;
use model::rack_type::{
    RackCapabilitiesSet, RackCapabilityCompute, RackFirmwareObjectConfig, RackHardwareTopology,
    RackProductFamily, RackProfile, RackProfileConfig,
};
use model::site_explorer::PreingestionState;

use crate::common;

const PROFILE_ID: &str = "rack-firmware-test";
const SOT: &str = "opaque SOT forwarded unchanged to RMS";
const TOKEN_NAME: &str = "rack-artifacts";
const TOKEN: &str = " opaque token\n";

#[derive(Debug, Default)]
struct StaticFirmwareObjectFetcher {
    calls: AtomicUsize,
}

#[async_trait]
impl FirmwareObjectFetcher for StaticFirmwareObjectFetcher {
    async fn fetch(&self, _url: &str, _timeout: Duration) -> Result<String, String> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(SOT.to_string())
    }
}

fn rack_profiles() -> RackProfileConfig {
    RackProfileConfig {
        rack_profiles: [(
            PROFILE_ID.to_string(),
            RackProfile {
                product_family: Some(RackProductFamily::Gb200),
                rack_hardware_topology: Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology),
                firmware_object: Some(RackFirmwareObjectConfig {
                    url: "https://firmware.example.invalid/sot.json".parse().unwrap(),
                    access_token_credential: Some(TOKEN_NAME.to_string()),
                    fetch_timeout: Duration::from_secs(30),
                }),
                rack_capabilities: RackCapabilitiesSet {
                    compute: RackCapabilityCompute {
                        vendor: Some("NVIDIA".to_string()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        )]
        .into(),
    }
}

fn manager(
    pool: &PgPool,
    env: &TestHarness,
    rms: Arc<MockRmsApi>,
    fetcher: Arc<StaticFirmwareObjectFetcher>,
) -> PreingestionManager {
    let mut config = default_config::get();
    config.ntp_servers.clear();
    let profiles = rack_profiles();

    let backend = Arc::new(RmsBackend::new(
        rms,
        None,
        pool.clone(),
        Arc::new(profiles.clone()),
        true,
    ));

    let component_manager = Arc::new(ComponentManager::new(
        backend.clone(),
        Arc::new(MockPowerShelfManager),
        backend,
        false,
        false,
        false,
    ));

    PreingestionManager::new(
        pool.clone(),
        config.preingestion_manager(),
        Arc::new(RedfishSim::default()),
        env.test_meter.meter(),
        None,
        None,
        Some(env.api().credential_manager().clone()),
        env.api().work_lock_manager_handle(),
        config.ntp_servers,
    )
    .with_rack_firmware(RackFirmwareDependencies::new(
        profiles,
        Some(component_manager),
        fetcher,
    ))
}

async fn test_env(pool: &PgPool) -> TestHarness {
    let env = TestHarness::builder(pool.clone()).build().await;
    let domain = env.test_domain().await;

    env.network_controller()
        .create_underlay_segment(&domain)
        .await;

    env
}

#[sqlx_test]
async fn expected_switch_does_not_use_compute_preingestion_firmware(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(&pool).await;

    let rack_id = RackId::from("rack-switch");
    let bmc_mac: MacAddress = "02:00:00:00:00:30".parse()?;
    let bmc_ip: IpAddr = "192.0.1.30".parse()?;
    let mut txn = pool.begin().await?;

    seed_expected_rack(txn.as_mut(), &rack_id).await?;

    db::expected_switch::create(
        txn.as_mut(),
        ExpectedSwitch {
            bmc_mac_address: bmc_mac,
            serial_number: "switch-1".to_string(),
            rack_id: Some(rack_id),
            bmc_ip_address: Some(bmc_ip),
            ..Default::default()
        },
    )
    .await?;

    db::machine_interface::preallocate_bmc_machine_interface(txn.as_mut(), bmc_mac, bmc_ip, None)
        .await?;

    seed_endpoint(txn.as_mut(), bmc_ip).await?;
    txn.commit().await?;

    let rms = Arc::new(MockRmsApi::new());

    let fetcher = Arc::new(StaticFirmwareObjectFetcher::default());

    manager(&pool, &env, rms.clone(), fetcher.clone())
        .run_single_iteration()
        .await?;

    assert!(rms.apply_firmware_object_calls().await.is_empty());
    assert_eq!(fetcher.calls.load(Ordering::Relaxed), 0);
    Ok(())
}

async fn seed_expected_rack(
    txn: &mut sqlx::PgConnection,
    rack_id: &RackId,
) -> Result<(), Box<dyn std::error::Error>> {
    db::expected_rack::create(
        txn,
        &ExpectedRack {
            rack_id: rack_id.clone(),
            rack_profile_id: RackProfileId::new(PROFILE_ID),
            ..Default::default()
        },
    )
    .await?;

    Ok(())
}

async fn seed_expected_compute_endpoint(
    txn: &mut sqlx::PgConnection,
    rack_id: &RackId,
    bmc_mac: MacAddress,
    bmc_ip: IpAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    db::expected_machine::create(
        &mut *txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: bmc_mac,
            data: ExpectedMachineData {
                serial_number: format!("compute-{bmc_mac}"),
                rack_id: Some(rack_id.clone()),
                ..Default::default()
            },
        },
    )
    .await?;

    db::machine_interface::preallocate_bmc_machine_interface(&mut *txn, bmc_mac, bmc_ip, None)
        .await?;

    seed_endpoint(txn, bmc_ip).await
}

async fn seed_endpoint(
    txn: &mut sqlx::PgConnection,
    address: IpAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    common::insert_endpoint_version(txn, &address.to_string(), "1", "1", false).await?;
    db::explored_endpoints::set_preingestion_recheck_versions(address, txn).await?;
    Ok(())
}

async fn seed_bmc_credentials(writer: &dyn CredentialWriter, bmc_mac: MacAddress) {
    writer
        .set_credentials(
            &CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot {
                    bmc_mac_address: bmc_mac,
                },
            },
            &Credentials::new("bmc-admin", "bmc-password"),
        )
        .await
        .expect("BMC credential setup should succeed");
}

async fn seed_artifact_token(writer: &dyn CredentialWriter) {
    writer
        .set_credentials(
            &CredentialKey::FirmwareArtifactAccessToken {
                name: TOKEN_NAME.to_string(),
            },
            &Credentials::new("", TOKEN),
        )
        .await
        .expect("artifact token setup should succeed");
}

async fn endpoint_state(pool: &PgPool, address: IpAddr) -> PreingestionState {
    db::explored_endpoints::find_by_ips(pool, vec![address])
        .await
        .unwrap()
        .pop()
        .unwrap()
        .preingestion_state
}

fn assert_request(
    request: &rms::ApplyFirmwareObjectRequest,
    rack_id: &RackId,
    bmc_ip: IpAddr,
    bmc_mac: MacAddress,
) {
    assert_eq!(request.rack_id, rack_id.to_string());
    assert_eq!(request.config_json, SOT);
    assert_eq!(request.access_token.as_deref(), Some(TOKEN));
    assert!(!request.force_update);
    assert!(request.component_filters.is_empty());
    assert!(request.node_descriptor_component_filters.is_empty());
    let nodes = request.nodes.as_ref().unwrap();
    assert_eq!(nodes.nodes.len(), 1);
    let node = &nodes.nodes[0];
    assert_eq!(node.node_id, bmc_mac.to_string());
    assert!(node.host_endpoint.is_none());

    assert_eq!(node.r#type, Some(rms::NodeType::ComputeGb200Nvidia as i32));

    let bmc_endpoint = node.bmc_endpoint.as_ref().unwrap();
    let bmc_interface = bmc_endpoint.interface.as_ref().unwrap();
    assert_eq!(bmc_interface.ip_address, bmc_ip.to_string());
    assert_eq!(bmc_interface.mac_address, bmc_mac.to_string());
}

#[sqlx_test]
async fn compute_submission_preserves_failed_alias_and_resumes_polling_after_restart(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(&pool).await;

    let rack_id = RackId::from("rack-compute");
    let bmc_mac: MacAddress = "02:00:00:00:00:10".parse()?;
    let addresses: [IpAddr; 2] = ["192.0.1.10".parse()?, "2001:db8::10".parse()?];
    let mut txn = pool.begin().await?;

    seed_expected_rack(txn.as_mut(), &rack_id).await?;
    seed_expected_compute_endpoint(txn.as_mut(), &rack_id, bmc_mac, addresses[0]).await?;

    let bmc_interface = db::machine_interface::find_by_mac_address(txn.as_mut(), bmc_mac)
        .await?
        .pop()
        .expect("preallocated BMC interface should exist");

    db::machine_interface_address::insert(
        txn.as_mut(),
        bmc_interface.id,
        addresses[1],
        AllocationType::Static,
    )
    .await?;

    seed_endpoint(txn.as_mut(), addresses[1]).await?;

    db::explored_endpoints::set_preingestion_failed(
        addresses[0],
        "previous rack firmware failure".into(),
        txn.as_mut(),
    )
    .await?;

    txn.commit().await?;
    seed_bmc_credentials(env.api().credential_manager().as_ref(), bmc_mac).await;
    seed_artifact_token(env.api().credential_manager().as_ref()).await;

    let rms = Arc::new(MockRmsApi::new());

    rms.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
        &bmc_mac.to_string(),
        "compute-job",
    )))
    .await;

    rms.enqueue_get_firmware_job_status(Ok(MockRmsApi::firmware_job_status_ok(
        rms::FirmwareJobState::Completed,
    )))
    .await;

    let fetcher = Arc::new(StaticFirmwareObjectFetcher::default());

    let preingestion_manager = manager(&pool, &env, rms.clone(), fetcher.clone());

    preingestion_manager.run_single_iteration().await?;

    assert_eq!(
        endpoint_state(&pool, addresses[1]).await,
        PreingestionState::RackFirmwareUpdateWait
    );

    assert_eq!(rms.apply_firmware_object_calls().await.len(), 1);

    assert_request(
        &rms.apply_firmware_object_calls().await[0],
        &rack_id,
        addresses[1],
        bmc_mac,
    );

    assert_eq!(fetcher.calls.load(Ordering::Relaxed), 1);

    assert_eq!(
        db::explored_endpoints::get_backend_firmware_object_job_id_by_ip(&pool, addresses[1])
            .await?
            .as_deref(),
        Some("compute-job")
    );

    drop(preingestion_manager);

    manager(&pool, &env, rms.clone(), fetcher)
        .run_single_iteration()
        .await?;

    assert_eq!(
        endpoint_state(&pool, addresses[0]).await,
        PreingestionState::Failed {
            reason: "previous rack firmware failure".into(),
        }
    );

    assert_eq!(
        endpoint_state(&pool, addresses[1]).await,
        PreingestionState::Complete
    );

    let completed_endpoint = db::explored_endpoints::find_by_ips(&pool, vec![addresses[1]])
        .await?
        .pop()
        .expect("completed endpoint should exist");

    assert!(completed_endpoint.waiting_for_explorer_refresh);

    assert_eq!(rms.apply_firmware_object_calls().await.len(), 1);
    Ok(())
}

#[sqlx_test]
async fn compute_uses_live_rack_profile_without_expected_rack(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(&pool).await;

    let rack_id = RackId::from("live-rack");
    let bmc_mac: MacAddress = "02:00:00:00:00:40".parse()?;
    let bmc_ip: IpAddr = "192.0.1.40".parse()?;
    let mut txn = pool.begin().await?;

    db::rack::create(
        txn.as_mut(),
        &rack_id,
        Some(&RackProfileId::new(PROFILE_ID)),
        &RackConfig::default(),
        None,
    )
    .await?;

    seed_expected_compute_endpoint(txn.as_mut(), &rack_id, bmc_mac, bmc_ip).await?;
    txn.commit().await?;
    seed_bmc_credentials(env.api().credential_manager().as_ref(), bmc_mac).await;
    seed_artifact_token(env.api().credential_manager().as_ref()).await;

    let rms = Arc::new(MockRmsApi::new());

    rms.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
        &bmc_mac.to_string(),
        "live-rack-job",
    )))
    .await;

    let fetcher = Arc::new(StaticFirmwareObjectFetcher::default());

    manager(&pool, &env, rms.clone(), fetcher)
        .run_single_iteration()
        .await?;

    assert_eq!(
        endpoint_state(&pool, bmc_ip).await,
        PreingestionState::RackFirmwareUpdateWait
    );

    assert_request(
        &rms.apply_firmware_object_calls().await[0],
        &rack_id,
        bmc_ip,
        bmc_mac,
    );

    Ok(())
}

#[sqlx_test]
async fn live_rack_without_profile_does_not_fall_back_to_expected_rack_profile(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(&pool).await;
    let rack_id = RackId::from("live-rack-without-profile");
    let bmc_mac: MacAddress = "02:00:00:00:00:41".parse()?;
    let bmc_ip: IpAddr = "192.0.1.41".parse()?;
    let mut txn = pool.begin().await?;

    seed_expected_rack(txn.as_mut(), &rack_id).await?;

    db::rack::create(txn.as_mut(), &rack_id, None, &RackConfig::default(), None).await?;

    seed_expected_compute_endpoint(txn.as_mut(), &rack_id, bmc_mac, bmc_ip).await?;
    txn.commit().await?;

    let rms = Arc::new(MockRmsApi::new());
    let fetcher = Arc::new(StaticFirmwareObjectFetcher::default());

    manager(&pool, &env, rms.clone(), fetcher.clone())
        .run_single_iteration()
        .await?;

    assert!(matches!(
        endpoint_state(&pool, bmc_ip).await,
        PreingestionState::Failed { reason }
            if reason.contains("has no rack profile for expected compute BMC MAC")
    ));

    assert!(rms.apply_firmware_object_calls().await.is_empty());
    assert_eq!(fetcher.calls.load(Ordering::Relaxed), 0);

    Ok(())
}

#[sqlx_test]
async fn interrupted_compute_submission_fails_closed(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(&pool).await;

    let rack_id = RackId::from("rack-interrupted-submission");
    let bmc_mac: MacAddress = "02:00:00:00:00:60".parse()?;
    let bmc_ip: IpAddr = "192.0.1.60".parse()?;
    let mut txn = pool.begin().await?;

    seed_expected_rack(txn.as_mut(), &rack_id).await?;
    seed_expected_compute_endpoint(txn.as_mut(), &rack_id, bmc_mac, bmc_ip).await?;

    assert!(
        db::explored_endpoints::claim_preingestion_rack_firmware_submitting(bmc_ip, txn.as_mut(),)
            .await?
    );

    txn.commit().await?;

    let rms = Arc::new(MockRmsApi::new());
    let fetcher = Arc::new(StaticFirmwareObjectFetcher::default());

    manager(&pool, &env, rms.clone(), fetcher)
        .run_single_iteration()
        .await?;

    assert!(matches!(
        endpoint_state(&pool, bmc_ip).await,
        PreingestionState::Failed { reason }
            if reason.contains("submission outcome is unknown after restart")
    ));

    assert!(rms.apply_firmware_object_calls().await.is_empty());

    Ok(())
}
