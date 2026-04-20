// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use carbide_uuid::power_shelf::{PowerShelfId, PowerShelfIdSource, PowerShelfType};
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::{SwitchId, SwitchIdSource, SwitchType};
use mac_address::MacAddress;
use model::expected_power_shelf::ExpectedPowerShelf;
use model::expected_switch::ExpectedSwitch;
use model::metadata::Metadata;
use model::power_shelf::{NewPowerShelf, PowerShelfConfig};
use model::rack::{RackConfig, RackState};
use model::switch::{NewSwitch, SwitchConfig};
use sqlx::PgPool;

pub(crate) const PS_MAC_1: &str = "AA:BB:CC:DD:EE:01";
pub(crate) const PS_MAC_2: &str = "AA:BB:CC:DD:EE:02";
pub(crate) const SW_MAC_1: &str = "AA:BB:CC:DD:FF:01";
pub(crate) const SW_MAC_2: &str = "AA:BB:CC:DD:FF:02";
pub(crate) const UNKNOWN_MAC: &str = "FF:FF:FF:FF:FF:FF";

pub(crate) fn test_power_shelf_id(label: &str) -> PowerShelfId {
    let mut hash = [0u8; 32];
    let bytes = label.as_bytes();
    hash[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    PowerShelfId::new(
        PowerShelfIdSource::ProductBoardChassisSerial,
        hash,
        PowerShelfType::Rack,
    )
}

pub(crate) fn test_switch_id(label: &str) -> SwitchId {
    let mut hash = [0u8; 32];
    let bytes = label.as_bytes();
    hash[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    SwitchId::new(SwitchIdSource::Tpm, hash, SwitchType::NvLink)
}

/// Seed a rack + two power shelves + two switches into the database. Returns
/// the IDs so tests can assert against them. The rack is transitioned into
/// `Ready` so component-manager wrapper preflight accepts it.
pub(crate) async fn seed_test_data(
    pool: &PgPool,
) -> (RackId, PowerShelfId, PowerShelfId, SwitchId, SwitchId) {
    let mut txn = pool.begin().await.unwrap();

    let rack_id = RackId::new(uuid::Uuid::new_v4().to_string());
    let rack = db::rack::create(&mut txn, &rack_id, None, &RackConfig::default(), None)
        .await
        .expect("failed to create rack");

    let ps1 = seed_power_shelf(&mut txn, PS_MAC_1, "PS-001", &rack_id).await;
    let ps2 = seed_power_shelf(&mut txn, PS_MAC_2, "PS-002", &rack_id).await;
    let sw1 = seed_switch(&mut txn, SW_MAC_1, "SW-001", &rack_id).await;
    let sw2 = seed_switch(&mut txn, SW_MAC_2, "SW-002", &rack_id).await;

    // Advance the freshly-created rack into Ready so on-demand-maintenance
    // preflight accepts it. Tests that want to exercise the non-Ready path
    // override the state after seeding via `set_rack_state`.
    let next_version = rack.controller_state.version.increment();
    let advanced = db::rack::try_update_controller_state(
        &mut txn,
        &rack_id,
        rack.controller_state.version,
        next_version,
        &RackState::Ready,
    )
    .await
    .expect("failed to advance rack to Ready");
    assert!(advanced, "rack controller_state version mismatch");

    txn.commit().await.unwrap();
    (rack_id, ps1, ps2, sw1, sw2)
}

/// Forcibly override the rack's controller state. Used by tests that want to
/// exercise preflight behaviour (e.g. rejecting a request when the rack is
/// mid-maintenance).
pub(crate) async fn set_rack_state(pool: &PgPool, rack_id: &RackId, state: RackState) {
    let mut txn = pool.begin().await.unwrap();
    let rack = db::rack::find_by(
        txn.as_mut(),
        db::ObjectColumnFilter::One(db::rack::IdColumn, rack_id),
    )
    .await
    .expect("find_by")
    .pop()
    .expect("rack exists");
    let next_version = rack.controller_state.version.increment();
    let advanced = db::rack::try_update_controller_state(
        &mut txn,
        rack_id,
        rack.controller_state.version,
        next_version,
        &state,
    )
    .await
    .expect("try_update_controller_state");
    assert!(advanced, "rack controller_state version mismatch");
    txn.commit().await.unwrap();
}

pub(crate) async fn seed_power_shelf(
    txn: &mut sqlx::PgConnection,
    mac: &str,
    label: &str,
    rack_id: &RackId,
) -> PowerShelfId {
    let ps_id = test_power_shelf_id(label);
    let mac: MacAddress = mac.parse().unwrap();

    db::expected_power_shelf::create(
        &mut *txn,
        ExpectedPowerShelf {
            expected_power_shelf_id: None,
            bmc_mac_address: mac,
            serial_number: label.to_owned(),
            bmc_username: "admin".into(),
            bmc_password: "pass".into(),
            bmc_ip_address: None,
            metadata: Metadata::default(),
            rack_id: Some(rack_id.clone()),
            bmc_retain_credentials: None,
        },
    )
    .await
    .expect("failed to create expected power shelf");

    db::power_shelf::create(
        &mut *txn,
        &NewPowerShelf {
            id: ps_id,
            config: PowerShelfConfig {
                name: label.to_owned(),
                capacity: None,
                voltage: None,
            },
            metadata: Some(Metadata::default()),
            rack_id: Some(rack_id.clone()),
        },
    )
    .await
    .expect("failed to create power shelf");

    sqlx::query("UPDATE power_shelves SET bmc_mac_address = $1 WHERE id = $2")
        .bind(mac)
        .bind(ps_id)
        .execute(&mut *txn)
        .await
        .expect("failed to set power shelf bmc_mac_address");

    ps_id
}

pub(crate) async fn seed_switch(
    txn: &mut sqlx::PgConnection,
    mac: &str,
    label: &str,
    rack_id: &RackId,
) -> SwitchId {
    let sw_id = test_switch_id(label);
    let mac: MacAddress = mac.parse().unwrap();

    db::expected_switch::create(
        &mut *txn,
        ExpectedSwitch {
            expected_switch_id: None,
            serial_number: label.to_owned(),
            bmc_mac_address: mac,
            bmc_ip_address: None,
            bmc_username: "admin".into(),
            bmc_password: "pass".into(),
            nvos_username: None,
            nvos_password: None,
            nvos_mac_addresses: vec![],
            metadata: Metadata::default(),
            rack_id: Some(rack_id.clone()),
            bmc_retain_credentials: None,
        },
    )
    .await
    .expect("failed to create expected switch");

    db::switch::create(
        &mut *txn,
        &NewSwitch {
            id: sw_id,
            config: SwitchConfig {
                name: label.to_owned(),
                enable_nmxc: false,
                fabric_manager_config: None,
            },
            bmc_mac_address: Some(mac),
            metadata: Some(Metadata::default()),
            rack_id: Some(rack_id.clone()),
            slot_number: None,
            tray_index: None,
        },
    )
    .await
    .expect("failed to create switch");

    sw_id
}
