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

use std::{
    collections::HashMap,
    env, fs,
    net::{SocketAddr, TcpListener},
    path::{self, PathBuf},
    time::{self, Duration},
};

use grpcurl::grpcurl;
use sqlx::{migrate::MigrateDatabase, Postgres, Row};
use tokio::time::sleep;

mod api_server;
mod dpu;
pub mod grpcurl;
mod host;
mod instance;
mod machine;
mod metrics;
mod subnet;
mod upgrade;
mod vault;
mod vpc;

/// Integration test that shells out to start the real carbide-api, and then does all the steps
/// that `bootstrap-forge-docker` would do.
/// It requires `grpcurl` and `vault` on the PATH,
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_integration() -> eyre::Result<()> {
    env::set_var("DISABLE_TLS_ENFORCEMENT", "true");
    env::set_var("IGNORE_MGMT_VRF", "true");
    // There is unfortunately no support for certificates in the vault dev server, so we have to disable this in code.
    env::set_var("UNSUPPORTED_CERTIFICATE_PROVIDER", "true");
    env::set_var("NO_DPU_CONTAINERS", "true");
    env::set_var("NO_DPU_ARMOS_NETWORK", "true");

    // We should setup logging here but:
    // - try_init sets a global logger and can only be called once.
    // Error is: "a global default trace dispatcher has already been set".
    // forge_host_support::init_logging() calls try_init, but so does carbide-api when it starts.
    // - Even if we could get around that (forge_host_support::subscriber().set_default() should
    // set a thread-specific logger), tracing will attempt to initialize the `log` crate (via tracing-log)
    // which can also only be initialized once. What a mess.
    // Error is: "attempted to set a logger after the logging system was already initialized"

    let Ok(repo_root) = env::var("REPO_ROOT").or_else(|_| env::var("CONTAINER_REPO_ROOT")) else {
        eprintln!(
            "Either REPO_ROOT or CONTAINER_REPO_ROOT need to be set to run this test. Skipping."
        );
        return Ok(());
    };
    let root_dir = PathBuf::from(repo_root.clone());
    let bins = find_prerequisites()?;

    // Put our fake `crictl` on front of path so that forge-dpu-agent's HBN health checks succeed
    let dev_bin = root_dir.join("dev/bin");
    if let Some(path) = env::var_os("PATH") {
        let mut paths = env::split_paths(&path).collect::<Vec<_>>();
        paths.insert(0, dev_bin);
        let new_path = env::join_paths(paths)?;
        env::set_var("PATH", new_path);
    }

    // We have to do [sqlx::test] 's work manually here so that we can use a multi-threaded executor
    let db_url = env::var("DATABASE_URL")? + "/test_integration";
    if sqlx::Postgres::database_exists(&db_url).await? {
        sqlx::Postgres::drop_database(&db_url).await?;
    }
    sqlx::Postgres::create_database(&db_url).await?;
    let db_pool = sqlx::Pool::<sqlx::postgres::Postgres>::connect(&db_url).await?;
    let m = sqlx::migrate!("../api/migrations");

    // Dependencies: Postgres, Vault and a Redfish BMC
    m.run(&db_pool).await?;
    let vault = vault::start(bins.get("vault").unwrap())?;
    let mut routers = HashMap::default();
    routers.insert(
        "".to_owned(),
        bmc_mock::default_router(bmc_mock::BmcState { use_qemu: false }),
    );
    tokio::spawn(bmc_mock::run(routers, None, None));

    // Ask OS for a free port
    let carbide_api_addr = {
        let l = TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?
    };
    // TODO: Also pick a free port for metrics
    let carbide_metrics_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();

    let vault_token = vault.token().to_string();
    let root_dir_clone = root_dir.to_str().unwrap().to_string();
    let db_url = db_url.to_string();
    tokio::spawn(async move {
        if let Err(e) =
            api_server::start(carbide_api_addr, root_dir_clone, db_url, vault_token).await
        {
            eprintln!("Failed to start API server: {:#}", e);
        }
    });

    sleep(time::Duration::from_secs(5)).await;

    // And now.. Behold! The Test!

    // Before the initial host bootstrap, the dns_records view
    // should contain 0 entries.
    assert_eq!(0i64, get_dns_record_count(&db_pool).await);

    let agent_config_file = tempfile::NamedTempFile::new()?;
    let upgrade_indicator_file = tempfile::NamedTempFile::new()?;
    let dpu_info = dpu::bootstrap(
        agent_config_file.path(),
        upgrade_indicator_file.path(),
        carbide_api_addr,
        &root_dir,
    )
    .await?;
    let host_machine_id = host_boostrap(carbide_api_addr).await?;

    // After the host_bootstrap, the dns_records view
    // should contain 6 entries:
    // - 2x "human friendly" for Host + DPU.
    // - 2x Machine ID (BMC) for Host + DPU.
    // - 2x Machine ID (ADM) for HOst + DPU.
    assert_eq!(6i64, get_dns_record_count(&db_pool).await);

    // Metrics are only updated after the machine state controller run one more
    // time since the emitted metrics are for states at the start of the iteration.
    // Therefore wait for the updated metrics to show up.
    let metrics = metrics::wait_for_metric_line(
        carbide_metrics_addr,
        r#"forge_machines_per_state{fresh="true",state="ready",substate=""} 1"#,
    )
    .await?;
    metrics::assert_metric_line(&metrics, r#"forge_machines_total{fresh="true"} 1"#);
    metrics::assert_not_metric_line(
        &metrics,
        "machine_reboot_attempts_in_booting_with_discovery_image",
    );

    upgrade::upgrade_dpu(
        upgrade_indicator_file.path(),
        carbide_api_addr,
        db_pool.clone(),
        &dpu_info.machine_id,
    )
    .await?;
    // An upgraded dpu-agent exits so that systemd can start the new version. Be systemd.
    tokio::spawn(agent::start(agent::Options {
        version: false,
        config_path: Some(agent_config_file.path().to_path_buf()),
        cmd: Some(agent::AgentCommand::Run(agent::RunOptions {
            enable_metadata_service: false,
            override_machine_id: Some(dpu_info.machine_id.clone()),
            override_network_virtualization_type: None,
            skip_upgrade_check: false,
        })),
    }));
    tokio::time::sleep(Duration::from_secs(1)).await;
    upgrade::confirm_upgraded(db_pool, &dpu_info.machine_id).await?;

    let vpc_id = vpc::create(carbide_api_addr)?;
    let segment_id = subnet::create(carbide_api_addr, &vpc_id)?;

    // Create instance with phone_home enabled
    let instance_id = instance::create(carbide_api_addr, &host_machine_id, &segment_id, true)?;
    let metrics = metrics::wait_for_metric_line(
        carbide_metrics_addr,
        r#"forge_machines_per_state{fresh="true",state="assigned",substate="ready"} 1"#,
    )
    .await?;
    metrics::assert_metric_line(&metrics, r#"forge_machines_total{fresh="true"} 1"#);
    metrics::assert_not_metric_line(
        &metrics,
        r#"forge_machines_per_state{fresh="true",state="ready",substate=""}"#,
    );
    metrics::assert_not_metric_line(
        &metrics,
        "machine_reboot_attempts_in_booting_with_discovery_image",
    );

    instance::release(carbide_api_addr, &host_machine_id, &instance_id)?;

    let metrics = metrics::wait_for_metric_line(carbide_metrics_addr, r#"forge_machines_per_state{fresh="true",state="waitingforcleanup",substate="hostcleanup"} 1"#).await?;
    metrics::assert_metric_line(&metrics, r#"forge_machines_total{fresh="true"} 1"#);

    machine::cleanup_completed(carbide_api_addr, &host_machine_id)?;
    machine::wait_for_state(carbide_api_addr, &host_machine_id, "Discovered")?;

    // It stays in Discovered until we notify that reboot happened, which this test doesn't
    let metrics = metrics::wait_for_metric_line(
        carbide_metrics_addr,
        r#"forge_machines_per_state{fresh="true",state="hostnotready",substate="discovered"} 1"#,
    )
    .await?;
    metrics::assert_not_metric_line(
        &metrics,
        r#"forge_machines_per_state{fresh="true",state="assigned""#,
    );

    // Explicitly test that the histogram for `forge_reboot_attempts_in_booting_with_discovery_image_bucket`
    // uses the custom buckets we defined for retries/attempts
    for &(bucket, count) in &[(0, 0), (1, 1), (2, 1), (3, 1), (5, 1), (10, 1)] {
        metrics::assert_metric_line(
            &metrics,
            &format!(
                r#"forge_reboot_attempts_in_booting_with_discovery_image_bucket{{le="{bucket}"}} {count}"#
            ),
        );
    }
    metrics::assert_not_metric_line(
        &metrics,
        r#"forge_reboot_attempts_in_booting_with_discovery_image_bucket{le="4"}"#,
    );
    metrics::assert_not_metric_line(
        &metrics,
        r#"forge_reboot_attempts_in_booting_with_discovery_image_bucket{le="6"}"#,
    );
    metrics::assert_metric_line(
        &metrics,
        r#"forge_reboot_attempts_in_booting_with_discovery_image_bucket{le="+Inf"} 1"#,
    );
    metrics::assert_metric_line(
        &metrics,
        "forge_reboot_attempts_in_booting_with_discovery_image_sum 1",
    );
    metrics::assert_metric_line(
        &metrics,
        "forge_reboot_attempts_in_booting_with_discovery_image_count 1",
    );

    sleep(time::Duration::from_millis(500)).await;
    fs::remove_dir_all(dpu_info.hbn_root)?;
    Ok(())
}

/// Bootstraps a Host in `ready` state. Returns the `machine_id`
async fn host_boostrap(carbide_api_addr: SocketAddr) -> eyre::Result<String> {
    let host_machine_id = host::bootstrap(carbide_api_addr)?;

    // Wait until carbide-api is prepared to admit the DPU might have rebooted.
    // There are hard coded sleeps in carbide-api before this happens.
    machine::wait_for_state(carbide_api_addr, &host_machine_id, "WaitForDPUUp")?;

    // After DPU reboot forge_dpu_agent reports health to carbide-api, triggering state transition
    machine::wait_for_state(carbide_api_addr, &host_machine_id, "Host/Discovered")?;

    grpcurl(
        carbide_api_addr,
        "ForgeAgentControl",
        Some(
            &serde_json::json!({
                "machine_id": {"id": host_machine_id}
            })
            .to_string(),
        ),
    )?;
    machine::wait_for_state(carbide_api_addr, &host_machine_id, "Ready")?;
    tracing::info!("ManagedHost is up in Ready state.");
    Ok(host_machine_id)
}

fn find_prerequisites() -> eyre::Result<HashMap<String, PathBuf>> {
    let mut bins = HashMap::with_capacity(2);
    let paths: Vec<path::PathBuf> = env::split_paths(&env::var_os("PATH").unwrap()).collect();
    bins.insert("vault", find_first_in("vault", &paths));
    bins.insert("grpcurl", find_first_in("grpcurl", &paths));
    bins.insert("curl", find_first_in("curl", &paths));

    let mut full_paths = HashMap::with_capacity(bins.len());
    for (k, v) in bins.drain() {
        match v {
            Some(full_path) => {
                full_paths.insert(k.to_string(), full_path);
            }
            None => {
                eyre::bail!("Missing prerequisite binary: {k}");
            }
        }
    }

    Ok(full_paths)
}

// Look for a binary in the given paths, return full path or None if not found
fn find_first_in(binary: &str, paths: &[path::PathBuf]) -> Option<path::PathBuf> {
    for path in paths {
        let candidate = path.join(binary);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

// Get the current number of rows in the dns_records view,
// which is expected to start at 0, and then progress, as
// the test continues.
//
// TODO(chet): Find a common place for this and the same exact
// function in api/tests/dns.rs to exist, instead of it being
// in two places.
pub async fn get_dns_record_count(pool: &sqlx::Pool<Postgres>) -> i64 {
    let mut txn = pool.begin().await.unwrap();
    let query = "SELECT COUNT(*) as row_cnt FROM dns_records";
    let rows = sqlx::query::<_>(query).fetch_one(&mut *txn).await.unwrap();
    rows.try_get("row_cnt").unwrap()
}
