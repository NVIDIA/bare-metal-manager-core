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

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};

use carbide::db::machine::{Machine, MachineSearchConfig};
use carbide::model::machine::machine_id::MachineId;
use carbide::CarbideError;
use sqlx::{Pool, Postgres};

use crate::grpcurl::grpcurl;

const HALF_SEC: Duration = Duration::from_millis(500);

/// Max amount of time to wait for forge-dpu-agent to upgrade itself
const MAX_UPGRADE_WAIT: Duration = Duration::from_secs(5);

/// Upgrade forge-dpu-agent
pub async fn upgrade_dpu(
    upgrade_indicator: &Path,
    carbide_api_addr: SocketAddr,
    db_pool: Pool<Postgres>,
    dpu_machine_id: &str,
) -> eyre::Result<()> {
    // 1 is UpOnly
    grpcurl(
        carbide_api_addr,
        "DpuAgentUpgradePolicyAction",
        Some(serde_json::json!({"new_policy": 1})),
    )?;

    // The DPU agent has the same version as carbide-api so we need to mark it for upgrade manually
    mark_agent_for_upgrade(&db_pool, dpu_machine_id).await?;

    attach_blocking_trigger(&db_pool).await?;

    // The command in dpu.rs DPU_CONFIG upgrade_cmd should run. Wait for it
    let expected_version = forge_version::v!(build_version)[1..].to_string();
    wait_for_upgrade(upgrade_indicator, &expected_version).await?;
    remove_blocking_trigger(&db_pool).await?;

    Ok(())
}

// DPU agent no longer marked for upgrade
pub async fn confirm_upgraded(db_pool: Pool<Postgres>, dpu_machine_id: &str) -> eyre::Result<()> {
    let mut txn = db_pool
        .begin()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "begin check needs_agent_upgrade", e))?;
    let machine = Machine::find_one(
        &mut txn,
        &MachineId::from_str(dpu_machine_id)?,
        MachineSearchConfig::default(),
    )
    .await?
    .unwrap();

    assert!(
        !machine.needs_agent_upgrade(),
        "Machine should be marked as upgraded"
    );

    txn.commit()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "commit check needs_agent_upgrade", e))?;

    Ok(())
}

/// This database trigger ensures the correct order of upgrade steps from bluefield/agent/src/lib.rs's main loop:
/// 1. `upgrade::upgrade_check` performs the upgrade
/// 2. `record_network_status` marks the upgrade as complete
///
/// We don't know in which order those steps will happen. It doesn't usually matter because the upgrade
/// won't be marked as complete until the version numbers match. However in the integration test the versions
/// already match, that's why we `mark_agent_for_upgrade`.
///
/// To ensure predictable order we attach a database trigger that blocks changes to the field (step 2 above).
/// Once step 1 has happened we remove the block.
async fn attach_blocking_trigger(db_pool: &Pool<Postgres>) -> eyre::Result<()> {
    let create_function = r#"
CREATE OR REPLACE FUNCTION integration_test_reset_needs_upgrade()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.dpu_agent_upgrade_requested := NEW.dpu_agent_upgrade_requested || '{"should_upgrade": true}';
  RETURN NEW;
END;
$$;
"#;
    sqlx::query(create_function).execute(db_pool).await?;

    let create_trigger = r#"
CREATE TRIGGER integration_test_block_upgrade_done_trigger
BEFORE UPDATE ON machines
FOR EACH ROW
WHEN ((NEW.dpu_agent_upgrade_requested->'should_upgrade')::bool = false)
EXECUTE PROCEDURE integration_test_reset_needs_upgrade()
"#;
    sqlx::query(create_trigger).execute(db_pool).await?;

    Ok(())
}

/// See expanation in attach_blocking_trigger
async fn remove_blocking_trigger(db_pool: &Pool<Postgres>) -> eyre::Result<()> {
    sqlx::query("DROP TRIGGER integration_test_block_upgrade_done_trigger ON machines")
        .execute(db_pool)
        .await?;
    sqlx::query("DROP FUNCTION integration_test_reset_needs_upgrade")
        .execute(db_pool)
        .await?;
    Ok(())
}

/// In the integration test the versions already match. Pretend they don't.
async fn mark_agent_for_upgrade(
    db_pool: &Pool<Postgres>,
    dpu_machine_id: &str,
) -> eyre::Result<()> {
    let mut txn = db_pool
        .begin()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "begin check needs_agent_upgrade", e))?;
    Machine::set_dpu_agent_upgrade_requested(
        &mut txn,
        &MachineId::from_str(dpu_machine_id).unwrap(),
        true,
        "v2023.09-82-gb7727207",
    )
    .await?;
    txn.commit()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "commit check needs_agent_upgrade", e))?;
    Ok(())
}

/// The upgrade writes a file in `/tmp`. Wait for it to have the correct contents.
async fn wait_for_upgrade(upgrade_indicator: &Path, expected_version: &str) -> eyre::Result<()> {
    let deadline = Instant::now() + MAX_UPGRADE_WAIT;
    while Instant::now() < deadline {
        if upgrade_indicator.exists()
            && fs::read_to_string(upgrade_indicator)?.contains(expected_version)
        {
            // Found it. Success
            return Ok(());
        }
        tokio::time::sleep(HALF_SEC).await;
    }
    eyre::bail!("wait_for_upgrade: Timeout. forge-dpu-agent did not upgrade itself");
}
