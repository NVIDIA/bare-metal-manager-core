use crate::db::ib_partition::IBPartition;
use crate::handlers::utils::convert_and_log_machine_id;
use crate::ib::IBFabricManager;
use crate::model::ConfigValidationError;
use crate::model::instance::config::network::{InstanceNetworkConfig, NetworkDetails};
use crate::model::instance::snapshot::InstanceSnapshot;
/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use crate::api::{Api, log_machine_id, log_request_data};
use crate::db::{
    self, DatabaseError,
    instance::{DeleteInstance, Instance},
    machine::MachineSearchConfig,
    managed_host::LoadSnapshotOptions,
    network_security_group,
};
use crate::instance::{InstanceAllocationRequest, allocate_instance, allocate_network};
use crate::model::instance::config::InstanceConfig;
use crate::model::instance::config::tenant_config::TenantConfig;
use crate::model::machine::{InstanceState, ManagedHostState, ManagedHostStateSnapshot};
use crate::model::metadata::Metadata;
use crate::model::os::OperatingSystem;
use crate::redfish::RedfishAuth;
use crate::resource_pool::common::CommonPools;
use crate::{CarbideError, CarbideResult};
use ::rpc::forge::{self as rpc, AdminForceDeleteMachineResponse};
use ::rpc::uuid::infiniband::IBPartitionId;
use ::rpc::uuid::instance::InstanceId;
use ::rpc::uuid::machine::MachineId;
use forge_secrets::credentials::{BmcCredentialType, CredentialKey};
use health_report::{
    HealthAlertClassification, HealthProbeAlert, HealthProbeId, HealthReport, OverrideMode,
};
use itertools::Itertools as _;
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub(crate) async fn allocate(
    api: &Api,
    request: Request<rpc::InstanceAllocationRequest>,
) -> Result<Response<rpc::Instance>, Status> {
    log_request_data(&request);

    let request = InstanceAllocationRequest::try_from(request.into_inner())?;

    log_machine_id(&request.machine_id);

    // Row-locking on Machine records happens in allocate_instance
    let mh_snapshot = allocate_instance(
        api,
        request,
        &api.database_connection,
        api.runtime_config.host_health,
    )
    .await?;

    Ok(Response::new(snapshot_to_instance(mh_snapshot)?))
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::InstanceSearchFilter>,
) -> Result<Response<rpc::InstanceIdList>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "instance::find_ids";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let filter: rpc::InstanceSearchFilter = request.into_inner();

    let instance_ids = Instance::find_ids(&mut txn, filter).await?;

    Ok(tonic::Response::new(rpc::InstanceIdList { instance_ids }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::InstancesByIdsRequest>,
) -> Result<Response<rpc::InstanceList>, Status> {
    log_request_data(&request);

    let instance_ids = request.into_inner().instance_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if instance_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if instance_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    const DB_TXN_NAME: &str = "instance::find_by_ids";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let snapshots = db::managed_host::load_by_instance_ids(
        &mut txn,
        instance_ids.as_ref(),
        LoadSnapshotOptions::default().with_host_health(api.runtime_config.host_health),
    )
    .await?;
    let mut instances = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots.into_iter() {
        instances.push(snapshot_to_instance(snapshot)?);
    }
    let _ = txn.rollback().await;

    Ok(Response::new(rpc::InstanceList { instances }))
}

// DEPRECATED: use find_ids and find_by_ids instead
pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::InstanceSearchQuery>,
) -> Result<Response<rpc::InstanceList>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "find_instances";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let rpc::InstanceSearchQuery { id, label, .. } = request.into_inner();
    let instance_ids = match (id, label) {
        (Some(id), None) => vec![id],
        (None, None) => Instance::find_ids(&mut txn, Default::default()).await?,
        (None, Some(label)) => {
            Instance::find_ids(
                &mut txn,
                rpc::InstanceSearchFilter {
                    label: Some(label),
                    ..Default::default()
                },
            )
            .await?
        }

        (Some(_id), Some(_label)) => {
            return Err(CarbideError::InvalidArgument(
                "Searching instances based on both id and labels is not supported.".to_string(),
            )
            .into());
        }
    };

    let snapshots = db::managed_host::load_by_instance_ids(
        &mut txn,
        &instance_ids,
        LoadSnapshotOptions::default().with_host_health(api.runtime_config.host_health),
    )
    .await?;

    // Convert snapshots to instances via [`snapshot_to_instance`]
    let instances = snapshots
        .into_iter()
        .map(snapshot_to_instance)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Response::new(rpc::InstanceList { instances }))
}

pub(crate) async fn find_by_machine_id(
    api: &Api,
    request: Request<MachineId>,
) -> Result<Response<rpc::InstanceList>, Status> {
    log_request_data(&request);

    let machine_id = convert_and_log_machine_id(Some(&request.into_inner()))?;

    const DB_TXN_NAME: &str = "find_instance_by_machine_id";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let mh_snapshot = match db::managed_host::load_snapshot(
        &mut txn,
        &machine_id,
        LoadSnapshotOptions::default().with_host_health(api.runtime_config.host_health),
    )
    .await
    {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return Ok(Response::new(rpc::InstanceList { instances: vec![] })),
        Err(e) => return Err(CarbideError::from(e).into()),
    };

    let maybe_instance =
        Option::<rpc::Instance>::try_from(mh_snapshot).map_err(CarbideError::from)?;

    let instances = if let Some(instance) = maybe_instance {
        vec![instance]
    } else {
        vec![]
    };

    let response = Response::new(rpc::InstanceList { instances });

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(response)
}

/// Creates a TenantReportedIssue health override template with issue details
fn create_tenant_reported_issue_override(issue: &rpc::Issue) -> HealthReport {
    HealthReport {
        source: "tenant-reported-issue".to_string(),
        observed_at: Some(chrono::Utc::now()),
        alerts: vec![HealthProbeAlert {
            id: HealthProbeId::from_str("TenantReportedIssue")
                .expect("TenantReportedIssue is a valid non-empty HealthProbeId"),
            target: Some("tenant-reported".to_string()),
            message: json!({
                "issue_category": format!("{:?}", rpc::IssueCategory::try_from(issue.category).unwrap_or(rpc::IssueCategory::Unspecified)),
                "summary": issue.summary,
                "details": issue.details
            }).to_string(),
            tenant_message: Some(format!("TenantReportedIssue: {}", issue.summary)),
            classifications: vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::suppress_external_alerting(),
            ],
            in_alert_since: None,
        }],
        ..Default::default()
    }
}

/// Creates a RequestRepair health override template
fn create_request_repair_override(issue: &rpc::Issue) -> HealthReport {
    HealthReport {
        source: "repair-request".to_string(),
        observed_at: Some(chrono::Utc::now()),
        alerts: vec![HealthProbeAlert {
            id: HealthProbeId::from_str("RequestRepair")
                .expect("RequestRepair is a valid non-empty HealthProbeId"),
            target: Some("repair-requested".to_string()),
            message: json!({
                "issue_category": format!("{:?}", rpc::IssueCategory::try_from(issue.category).unwrap_or(rpc::IssueCategory::Unspecified)),
                "summary": issue.summary,
                "details": issue.details
            }).to_string(),
            tenant_message: Some(format!(
                "RepairSystem: Node ready for repair - {}",
                issue.summary
            )),
            classifications: vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::suppress_external_alerting(),
            ],
            in_alert_since: None,
        }],
        ..Default::default()
    }
}

/// Helper function to apply health override with consistent error handling
async fn apply_health_override(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
    override_report: &HealthReport,
    operation_desc: &str,
) -> Result<(), CarbideError> {
    db::machine::insert_health_report_override(
        txn,
        machine_id,
        OverrideMode::Merge,
        override_report,
        false,
    )
    .await
    .map_err(|e| {
        tracing::error!(
            machine_id = %machine_id,
            error = ?e,
            operation = %operation_desc,
            "Failed to apply health override"
        );
        CarbideError::from(e)
    })?;

    tracing::info!(
        machine_id = %machine_id,
        operation = %operation_desc,
        "Successfully applied health override"
    );
    Ok(())
}

/// Helper function to remove health override with consistent error handling
async fn remove_health_override(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
    source: &str,
    operation_desc: &str,
) -> Result<(), CarbideError> {
    db::machine::remove_health_report_override(txn, machine_id, OverrideMode::Merge, source)
        .await
        .map_err(|e| {
            tracing::error!(
                machine_id = %machine_id,
                error = ?e,
                operation = %operation_desc,
                "Failed to remove health override"
            );
            CarbideError::from(e)
        })?;

    tracing::info!(
        machine_id = %machine_id,
        operation = %operation_desc,
        "Successfully removed health override"
    );
    Ok(())
}

/// Handles the Instance Release workflow when released from the Repair tenant.
///
/// This function implements the logic for when the RepairSystem releases an instance after
/// attempting repairs. It manages the transition from RequestRepair overrides to appropriate
/// final states based on repair outcomes.
///
/// ## Workflow Logic
///
/// ### No RequestRepair Override Present
/// - If issues are reported: Applies TenantReportedIssue (no auto-repair to prevent cycles)
/// - If no issues: No action taken (machine is healthy)
///
/// ### RequestRepair Override Present
/// - Checks machine metadata for `repair_status` label
/// - **Repair Completed**: Removes RequestRepair, handles any new issues without auto-repair
/// - **Repair Incomplete**: Remove RequestRepair override and replace with TenantReportedIssue
///   to transition back to manual intervention by the Forge team.
///
/// ## Infinite Cycle Prevention
/// The function specifically avoids triggering auto-repair (RequestRepair) for repair tenant
/// releases to prevent infinite loops where RepairSystem triggers itself repeatedly.
async fn handle_instance_release_from_repair_tenant(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
    issue: Option<&rpc::Issue>,
    machine: &crate::model::machine::Machine,
) -> Result<(), CarbideError> {
    let has_request_repair = machine
        .health_report_overrides
        .merges
        .contains_key("repair-request");

    if !has_request_repair {
        // No existing RequestRepair override
        if let Some(issue) = issue {
            tracing::info!(
                machine_id = %machine_id,
                issue_category = ?issue.category,
                issue_summary = %issue.summary,
                "Repair tenant reports issues on machine without RequestRepair override"
            );

            let override_report = create_tenant_reported_issue_override(issue);
            apply_health_override(
                txn,
                machine_id,
                &override_report,
                "TenantReportedIssue for repair tenant issues (no auto-repair to prevent cycles)",
            )
            .await?;
        } else {
            tracing::info!(
                machine_id = %machine_id,
                "Repair tenant release on machine without RequestRepair override and no issues - no action needed"
            );
        }
        return Ok(());
    }

    // Machine has RequestRepair override - check repair status
    let repair_status = machine.metadata.labels.get("repair_status").cloned();

    tracing::info!(
        machine_id = %machine_id,
        repair_status = ?repair_status,
        "Processing repair tenant release with repair status"
    );

    if repair_status.as_deref() == Some("Completed") {
        // Repair completed successfully - Good to remove the RequestRepair override.
        remove_health_override(
            txn,
            machine_id,
            "repair-request",
            "RequestRepair removed - repair completed successfully",
        )
        .await?;

        // Repair completed successfully - Apply TenantReportedIssue override if new
        // issues reported, else remove it to make machine available in ready pool.
        // Skipped applying RequestRepair override to avoid infinite loops.
        if let Some(issue) = issue {
            tracing::info!(
                machine_id = %machine_id,
                issue_category = ?issue.category,
                issue_summary = %issue.summary,
                "Repair tenant reports new issues after repair completion"
            );

            let override_report = create_tenant_reported_issue_override(issue);
            apply_health_override(
                txn,
                machine_id,
                &override_report,
                "TenantReportedIssue updated for repair tenant (no auto-repair to prevent cycles)",
            )
            .await?;
        } else {
            // No new issues - Remove TenantReportedIssue override to make machine available in ready pool
            remove_health_override(
                txn,
                machine_id,
                "tenant-reported-issue",
                "TenantReportedIssue removed - repair completed successfully",
            )
            .await?;
        }
    } else {
        // Repair failed - Remove the existing RequestRepair override and set TenantReportedIssue
        // to send the machine for Forge team intervention, preventing auto-repair loops.
        remove_health_override(
            txn,
            machine_id,
            "repair-request",
            "RequestRepair removed for incomplete repair",
        )
        .await?;

        // Determine which issue to use
        let issue_to_apply = if let Some(issue) = issue {
            tracing::info!(
                machine_id = %machine_id,
                issue_category = ?issue.category,
                issue_summary = %issue.summary,
                "Using tenant-provided issue details for incomplete repair"
            );
            issue.clone()
        } else {
            tracing::info!(
                machine_id = %machine_id,
                repair_status = ?repair_status,
                "Creating fallback issue for incomplete repair"
            );
            rpc::Issue {
                category: rpc::IssueCategory::Other as i32,
                summary: "RepairSystem processing incomplete".to_string(),
                details: format!(
                    "Machine released by repair tenant but repair status is: {:?}",
                    repair_status.as_deref().unwrap_or("Unknown")
                ),
            }
        };

        let override_report = create_tenant_reported_issue_override(&issue_to_apply);
        apply_health_override(
            txn,
            machine_id,
            &override_report,
            "TenantReportedIssue for incomplete repair (no auto-repair to prevent cycles)",
        )
        .await?;
    }

    Ok(())
}

/// Handles regular (non-repair) tenant workflow when releasing instances with reported issues.
///
/// This function implements the standard workflow for normal tenant instance releases that
/// include issue reports. It applies appropriate health overrides and conditionally triggers
/// auto-repair based on global configuration.
///
/// ## Workflow Steps
/// 1. **Always applies TenantReportedIssue**: Documents the reported issue in health overrides
/// 2. **Conditionally applies RequestRepair**: Only if auto-repair is enabled globally
///
/// ## Auto-Repair Logic
/// - **Enabled**: Applies both TenantReportedIssue and RequestRepair overrides
/// - **Disabled**: Applies only TenantReportedIssue override
///
/// The RequestRepair override signals the RepairSystem to attempt automated repairs
/// on the machine before it can be allocated to new instances.
async fn handle_instance_release_from_regular_tenant_and_report_issue(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
    issue: &rpc::Issue,
    auto_repair_enabled: bool,
) -> Result<(), CarbideError> {
    tracing::info!(
        machine_id = %machine_id,
        issue_category = ?issue.category,
        issue_summary = %issue.summary,
        "Regular tenant reported issue during instance release"
    );

    // Apply TenantReportedIssue health override
    let tenant_override = create_tenant_reported_issue_override(issue);
    apply_health_override(
        txn,
        machine_id,
        &tenant_override,
        "TenantReportedIssue for regular tenant",
    )
    .await?;

    // Apply RequestRepair if auto-repair is enabled
    if auto_repair_enabled {
        let repair_override = create_request_repair_override(issue);
        apply_health_override(
            txn,
            machine_id,
            &repair_override,
            "RequestRepair for regular tenant (auto-repair enabled)",
        )
        .await?;
    } else {
        tracing::info!(
            machine_id = %machine_id,
            "Auto-repair disabled - only applied TenantReportedIssue for regular tenant"
        );
    }

    Ok(())
}

/// Handles instance release requests with support for the Forge-RepairSystem integration.
///
/// This function processes instance deletion requests and applies appropriate health overrides
/// based on the requesting tenant type and reported issues. It supports two main workflows:
///
/// ## Repair Tenant Workflow
/// When `is_repair_tenant=true`, this indicates the RepairSystem is releasing an instance after
/// attempting repairs. The function:
/// - Checks for existing RequestRepair overrides on the machine
/// - Examines the repair status from machine metadata labels
/// - Removes RequestRepair overrides and applies TenantReportedIssue based on repair outcome
/// - Prevents infinite repair cycles by not triggering auto-repair for repair tenant releases
///
/// ## Regular Tenant Workflow
/// For normal tenant releases with reported issues:
/// - Always applies TenantReportedIssue health override to document the problem
/// - Conditionally applies RequestRepair override if auto-repair is enabled globally
/// - Respects the auto_machine_repair_plugin configuration setting
///
/// ## Health Override Sources
/// - `tenant-reported-issue`: Applied for all tenant-reported issues
/// - `repair-request`: Applied when auto-repair is enabled (regular tenants only)
pub(crate) async fn release(
    api: &Api,
    request: Request<rpc::InstanceReleaseRequest>,
) -> Result<Response<rpc::InstanceReleaseResult>, Status> {
    log_request_data(&request);
    let delete_instance = DeleteInstance::try_from(request.into_inner())?;

    const DB_TXN_NAME: &str = "release_instance";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let instance = Instance::find_by_id(&mut txn, delete_instance.instance_id)
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "instance",
            id: delete_instance.instance_id.to_string(),
        })?;

    log_machine_id(&instance.machine_id);

    // Instance Release called from the Repair tenant.
    if delete_instance.is_repair_tenant == Some(true) {
        tracing::info!(
            instance_id = %delete_instance.instance_id,
            machine_id = %instance.machine_id,
            has_issues = delete_instance.issue.is_some(),
            "Instance release requested by repair tenant"
        );

        // Get machine details for repair tenant workflow
        let machine = db::machine::find_one(
            &mut txn,
            &instance.machine_id,
            MachineSearchConfig {
                for_update: false,
                ..Default::default()
            },
        )
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine",
            id: instance.machine_id.to_string(),
        })?;

        // Handle repair tenant workflow
        handle_instance_release_from_repair_tenant(
            &mut txn,
            &instance.machine_id,
            delete_instance.issue.as_ref(),
            &machine,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    } else if let Some(issue) = &delete_instance.issue {
        // Instance Release called from the regular tenant (not the Repair tenant) and has an issue to report.
        let auto_repair_enabled = api.runtime_config.auto_machine_repair_plugin.enabled;

        handle_instance_release_from_regular_tenant_and_report_issue(
            &mut txn,
            &instance.machine_id,
            issue,
            auto_repair_enabled,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    }

    if instance.deleted.is_some() {
        tracing::info!(
            instance_id = %delete_instance.instance_id,
            "Instance is already marked for deletion.",
        );
        return Ok(Response::new(rpc::InstanceReleaseResult {}));
    }

    // TODO: This is racy. If the instance just got deleted we still
    // see an error here that is not returned as `NotFound` error. Ideally
    // we convert this case of the DatabaseError into NotFound too.
    delete_instance.mark_as_deleted(&mut txn).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(Response::new(rpc::InstanceReleaseResult {}))
}

pub(crate) async fn update_phone_home_last_contact(
    api: &Api,
    request: Request<rpc::InstancePhoneHomeLastContactRequest>,
) -> Result<Response<rpc::InstancePhoneHomeLastContactResponse>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let instance_id = request
        .instance_id
        .ok_or(CarbideError::MissingArgument("id"))?;

    const DB_TXN_NAME: &str = "update_instance_phone_home_last_contact";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let instance = Instance::find_by_id(&mut txn, instance_id)
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "instance",
            id: instance_id.to_string(),
        })?;

    log_machine_id(&instance.machine_id);

    let res = Instance::update_phone_home_last_contact(&mut txn, instance.id).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(Response::new(rpc::InstancePhoneHomeLastContactResponse {
        timestamp: Some(res.into()),
    }))
}

pub(crate) async fn invoke_power(
    api: &Api,
    request: Request<rpc::InstancePowerRequest>,
) -> Result<Response<rpc::InstancePowerResult>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "invoke_instance_power";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let request = request.into_inner();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &machine_id,
        LoadSnapshotOptions::default().with_host_health(api.runtime_config.host_health),
    )
    .await?
    .ok_or(CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;
    if snapshot.instance.is_none() {
        return Err(Status::invalid_argument(format!(
            "Supplied machine ID does not match an instance: {machine_id}"
        )));
    }
    let bmc_ip =
        snapshot
            .host_snapshot
            .bmc_info
            .ip
            .as_ref()
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "bmc_ip",
                id: machine_id.to_string(),
            })?;

    let run_provisioning_instructions_on_every_boot = snapshot
        .instance
        .map(|instance| {
            instance
                .config
                .os
                .run_provisioning_instructions_on_every_boot
        })
        .unwrap_or_default();

    if !run_provisioning_instructions_on_every_boot {
        Instance::use_custom_ipxe_on_next_boot(
            &machine_id,
            request.boot_with_custom_ipxe,
            &mut txn,
        )
        .await?;
    }

    // Check if reprovision is requested.
    // TODO: multidpu: Fix it for multiple dpus.
    let mut reprovision_handled = false;
    if request.apply_updates_on_reboot {
        for dpu_snapshot in &snapshot.dpu_snapshots {
            let Some(rr) = &dpu_snapshot.reprovision_requested else {
                continue;
            };

            if rr.started_at.is_some() {
                return Err(CarbideError::DpuReprovisioningInProgress(format!(
                    "Can't reboot host: {machine_id}"
                ))
                .into());
            }

            reprovision_handled = true;

            // This will trigger DPU reprovisioning/update via state machine.
            db::machine::approve_dpu_reprovision_request(&dpu_snapshot.id, &mut txn)
                .await
                .map_err(|err| {
                    // print actual error for debugging, but don't leak internal info to user.
                    tracing::error!(machine=%machine_id, "{:?}", err);

                    // TODO: What does this error actually mean
                    CarbideError::internal(
                        "Internal Failure. Try again after some time.".to_string(),
                    )
                })?;
        }
        if snapshot.host_snapshot.host_reprovision_requested.is_some() {
            reprovision_handled = true;

            db::machine::approve_host_reprovision_request(&snapshot.host_snapshot.id, &mut txn)
                .await
                .map_err(|err| {
                    // print actual error for debugging, but don't leak internal info to user.
                    tracing::error!(machine=%machine_id, "{:?}", err);

                    CarbideError::internal(
                        "Internal Failure. Try again after some time.".to_string(),
                    )
                })?;
        }
    }

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    if reprovision_handled {
        // Host will reboot once DPU reprovisioning is successfully finished.
        return Ok(Response::new(rpc::InstancePowerResult {}));
    }

    let bmc_mac_address =
        snapshot
            .host_snapshot
            .bmc_info
            .mac
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "bmc_mac",
                id: machine_id.to_string(),
            })?;

    // TODO: The API call should maybe not directly trigger the reboot
    // but instead queue it for the state handler. That will avoid racing
    // with other internal reboot requests from the state handler.
    let client = api
        .redfish_pool
        .create_client(
            bmc_ip,
            snapshot.host_snapshot.bmc_info.port,
            RedfishAuth::Key(CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
            }),
            true,
        )
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    // Lenovo does not yet provide a BMC lockdown so a user could
    // change the boot order which we set in `libredfish::forge_setup`.
    // We also can't call `boot_once` for other vendors because lockdown
    // prevents it.
    if snapshot.host_snapshot.bmc_vendor().is_lenovo() {
        client
            .boot_once(libredfish::Boot::Pxe)
            .await
            .map_err(CarbideError::from)?;
    }
    client
        .power(libredfish::SystemPowerControl::ForceRestart)
        .await
        .map_err(|e| CarbideError::internal(format!("Failed redfish ForceRestart subtask: {e}")))?;

    Ok(Response::new(rpc::InstancePowerResult {}))
}

pub(crate) async fn update_operating_system(
    api: &Api,
    request: Request<rpc::InstanceOperatingSystemUpdateRequest>,
) -> Result<Response<rpc::Instance>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let instance_id = request
        .instance_id
        .ok_or(CarbideError::MissingArgument("id"))?;

    let os: OperatingSystem = match request.os {
        None => return Err(CarbideError::MissingArgument("os").into()),
        Some(os) => os.try_into().map_err(CarbideError::from)?,
    };
    os.validate().map_err(CarbideError::from)?;

    const DB_TXN_NAME: &str = "update_instance_operating_system";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let instance =
        Instance::find_by_id(&mut txn, instance_id)
            .await?
            .ok_or(CarbideError::NotFoundError {
                kind: "instance",
                id: instance_id.to_string(),
            })?;

    log_machine_id(&instance.machine_id);

    if instance.deleted.is_some() {
        return Err(CarbideError::InvalidArgument(
            "Configuration for a terminating instance can not be changed".to_string(),
        )
        .into());
    }

    let expected_version = match request.if_version_match {
        Some(version) => version.parse().map_err(CarbideError::from)?,
        None => instance.config_version,
    };

    Instance::update_os(&mut txn, instance.id, expected_version, os).await?;

    let mh_snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &instance.machine_id,
        LoadSnapshotOptions::default().with_host_health(api.runtime_config.host_health),
    )
    .await?
    .ok_or(CarbideError::NotFoundError {
        kind: "instance",
        id: instance_id.to_string(),
    })?;
    let instance = snapshot_to_instance(mh_snapshot)?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(Response::new(instance))
}

pub(crate) async fn update_instance_config(
    api: &Api,
    request: tonic::Request<rpc::InstanceConfigUpdateRequest>,
) -> Result<tonic::Response<rpc::Instance>, Status> {
    log_request_data(&request);

    let request = request.into_inner();

    let instance_id = request
        .instance_id
        .ok_or(CarbideError::MissingArgument("id"))?;

    let mut config: InstanceConfig = match request.config {
        None => return Err(CarbideError::MissingArgument("config").into()),
        Some(config) => config.try_into().map_err(CarbideError::from)?,
    };

    // Network validation is done only if network update is requested.
    config.validate(false).map_err(CarbideError::from)?;

    // TODO: Should a missing metadata field
    // - be an error
    // - lead to writing empty metadata (same as initial instance creation will do)
    // - keep existing metadata
    let metadata: Metadata = match request.metadata {
        None => return Err(CarbideError::MissingArgument("metadata").into()),
        Some(metadata) => metadata.try_into().map_err(CarbideError::from)?,
    };
    metadata.validate(true).map_err(|e| {
        CarbideError::InvalidArgument(format!("Instance metadata is not valid: {e}"))
    })?;

    const DB_TXN_NAME: &str = "update_instance_config";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let instance =
        Instance::find_by_id(&mut txn, instance_id)
            .await?
            .ok_or(CarbideError::NotFoundError {
                kind: "instance",
                id: instance_id.to_string(),
            })?;

    log_machine_id(&instance.machine_id);

    let mh_snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &instance.machine_id,
        LoadSnapshotOptions::default().with_host_health(api.runtime_config.host_health),
    )
    .await?
    .ok_or(CarbideError::NotFoundError {
        kind: "instance",
        id: instance_id.to_string(),
    })?;

    if mh_snapshot
        .instance
        .as_ref()
        .map(|instance| instance.deleted.is_some())
        .unwrap_or(true)
    {
        return Err(CarbideError::InvalidArgument(
            "Configuration for a terminating instance can not be changed".to_string(),
        )
        .into());
    }

    // Check whether the update is allowed
    instance
        .config
        .verify_update_allowed_to(&config)
        .map_err(CarbideError::from)?;

    let expected_version = match request.if_version_match {
        Some(version) => version.parse().map_err(CarbideError::from)?,
        None => instance.config_version,
    };

    // If an NSG is applied, we need to do a little more validation.
    if let InstanceConfig {
        network_security_group_id: Some(ref nsg_id),
        tenant:
            TenantConfig {
                tenant_organization_id: ref tenant_org,
                ..
            },
        ..
    } = config
    {
        // Query to check the validity of the NSG ID but to also grab
        // a row-level lock on it if it exists.
        if network_security_group::find_by_ids(&mut txn, &[nsg_id.clone()], Some(tenant_org), true)
            .await?
            .pop()
            .is_none()
        {
            return Err(CarbideError::FailedPrecondition(format!(
                "NetworkSecurityGroup `{}` does not exist or is not owned by Tenant `{}`",
                nsg_id,
                tenant_org.clone(),
            ))
            .into());
        }
    }

    update_instance_network_config(
        &instance,
        &mut config.network,
        mh_snapshot.host_snapshot.current_state(),
        &mut txn,
    )
    .await?;
    Instance::update_config(&mut txn, instance.id, expected_version, config, metadata).await?;

    let mh_snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &instance.machine_id,
        LoadSnapshotOptions::default().with_host_health(api.runtime_config.host_health),
    )
    .await?
    .ok_or(CarbideError::NotFoundError {
        kind: "instance",
        id: instance_id.to_string(),
    })?;
    let instance = snapshot_to_instance(mh_snapshot)?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(Response::new(instance))
}

/// This function checks if network config update is requested and update db to initiate the
/// process.
///
/// If it is requested, validate if update is allowed or not. If update is allowed, copy existing
/// resources to avoid re-allocation, allocate resources for new interfaces and update the db to
/// indicate the state machine to start updating network on DPUs. This function also increments
/// network_config_version.
async fn update_instance_network_config(
    instance: &InstanceSnapshot,
    network: &mut InstanceNetworkConfig,
    mh_state: &ManagedHostState,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), CarbideError> {
    if instance.update_network_config_request.is_some() {
        return Err(ConfigValidationError::InstanceNetworkConfigUpdateAlreadyInProgress.into());
    }

    if !instance
        .config
        .network
        .is_network_config_update_requested(network)
    {
        return Ok(());
    }

    if !matches!(
        mh_state,
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready,
        }
    ) {
        return Err(ConfigValidationError::InvalidState.into());
    }

    if instance.deleted.is_some() {
        return Err(ConfigValidationError::InstanceDeletionIsRequested.into());
    }

    // This is the use case of adding/removing new VF.
    // Copy the resources if same interface and network are mentioned.
    network.copy_existing_resources(&instance.config.network);

    // Allocate network segment here if vpc_prefix_id is mentioned before validate.
    allocate_network(network, txn).await?;
    network.validate().map_err(CarbideError::from)?;

    let mh_snapshot =
        db::managed_host::load_snapshot(txn, &instance.machine_id, LoadSnapshotOptions::default())
            .await?
            .ok_or(CarbideError::NotFoundError {
                kind: "machine",
                id: instance.machine_id.to_string(),
            })?;

    // Allocate IP
    let updated_network_config = network
        .clone()
        // Allocate IPs and add them to the network config
        .with_allocated_ips(txn, instance.id, &mh_snapshot.host_snapshot)
        .await?;

    // Update network config in db.
    Instance::trigger_update_network_config_request(
        &instance.id,
        &instance.config.network,
        &updated_network_config,
        txn,
    )
    .await?;

    Ok(())
}

/// Extracts the RPC representation of Instances from a ManagedHost snapshot
///
/// This method expects that the snapshot must contain an instance definition.
/// If this is not required, then `Option::<rpc::Instance>::try_from(mh_snapshot)`
/// can be utilized.
fn snapshot_to_instance(
    mh_snapshot: ManagedHostStateSnapshot,
) -> Result<rpc::Instance, CarbideError> {
    let machine_id = mh_snapshot.host_snapshot.id;
    Option::<rpc::Instance>::try_from(mh_snapshot)
        .map_err(CarbideError::from)?
        .ok_or_else(|| {
            CarbideError::internal(format!(
                "Instance on Machine {machine_id} can be converted from snapshot"
            ))
        })
}

pub async fn force_delete_instance(
    instance_id: InstanceId,
    ib_fabric_manager: &Arc<dyn IBFabricManager>,
    common_pools: &Arc<CommonPools>,
    response: &mut AdminForceDeleteMachineResponse,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> CarbideResult<()> {
    let instance = Instance::find_by_id(txn, instance_id)
        .await?
        .ok_or_else(|| {
            CarbideError::internal(format!("Could not find an instance for {instance_id}"))
        })?
        .to_owned();

    let ib_fabric = ib_fabric_manager
        .connect(crate::ib::DEFAULT_IB_FABRIC_NAME)
        .await?;

    // Collect the ib partition and ib ports information about this machine
    let mut ib_config_map: HashMap<IBPartitionId, Vec<String>> = HashMap::new();
    let infiniband = instance.config.infiniband.ib_interfaces;
    for ib in &infiniband {
        let ib_partition_id = ib.ib_partition_id;
        if let Some(guid) = ib.guid.as_deref() {
            ib_config_map
                .entry(ib_partition_id)
                .or_default()
                .push(guid.to_string());
        }
    }

    response.ufm_unregistration_pending = true;
    // unbind ib ports from UFM
    for (ib_partition_id, guids) in ib_config_map.iter() {
        if let Some(pkey) = IBPartition::find_pkey_by_partition_id(txn, *ib_partition_id).await? {
            ib_fabric.unbind_ib_ports(pkey, guids.to_vec()).await?;
            response.ufm_unregistrations += 1;

            //TODO: release VF GUID resource when VF supported.
        }
    }
    response.ufm_unregistration_pending = false;

    // Delete the instance and allocated address
    // TODO: This might need some changes with the new state machine
    let delete_instance = DeleteInstance {
        instance_id,
        issue: None,
        is_repair_tenant: None,
    };
    delete_instance.delete(txn).await?;

    let mut network_segment_ids_with_vpc = vec![];
    if let Some(update_network_req) = &instance.update_network_config_request {
        // Not sure if new config is applied yet. Free all the resources.
        let mut addresses = update_network_req
            .new_config
            .interfaces
            .iter()
            .flat_map(|x| x.ip_addrs.values().collect_vec())
            .collect_vec();

        addresses.extend(
            update_network_req
                .old_config
                .interfaces
                .iter()
                .flat_map(|x| x.ip_addrs.values().collect_vec()),
        );

        db::instance_address::InstanceAddress::delete_addresses(txn, &addresses).await?;

        network_segment_ids_with_vpc = update_network_req
            .new_config
            .interfaces
            .iter()
            .filter_map(|x| match x.network_details {
                Some(NetworkDetails::VpcPrefixId(_)) => x.network_segment_id,
                _ => None,
            })
            .collect_vec();
        network_segment_ids_with_vpc.extend(
            update_network_req
                .old_config
                .interfaces
                .iter()
                .filter_map(|x| match x.network_details {
                    Some(NetworkDetails::VpcPrefixId(_)) => x.network_segment_id,
                    _ => None,
                }),
        );
    }

    network_segment_ids_with_vpc.extend(instance.config.network.interfaces.iter().filter_map(
        |x| match x.network_details {
            Some(NetworkDetails::VpcPrefixId(_)) => x.network_segment_id,
            _ => None,
        },
    ));

    let network_segments_set: std::collections::HashSet<::rpc::uuid::network::NetworkSegmentId> =
        network_segment_ids_with_vpc.drain(..).collect();
    network_segment_ids_with_vpc.extend(network_segments_set.into_iter());

    // Mark all network ready for delete which were created for vpc_prefixes.
    if !network_segment_ids_with_vpc.is_empty() {
        db::network_segment::NetworkSegment::mark_as_deleted_no_validation(
            txn,
            &network_segment_ids_with_vpc,
        )
        .await?;
    }

    let snapshot =
        db::managed_host::load_snapshot(txn, &instance.machine_id, LoadSnapshotOptions::default())
            .await?
            .ok_or(CarbideError::NotFoundError {
                kind: "machine",
                id: instance.machine_id.to_string(),
            })?;

    crate::state_controller::machine::handler::release_vpc_dpu_loopback(
        &snapshot,
        &Some(common_pools.clone()),
        txn,
    )
    .await
    .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(())
}
