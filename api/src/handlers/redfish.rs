use ::rpc::forge::{self as rpc};
use forge_secrets::credentials::{BmcCredentialType, CredentialKey};
use libredfish::Redfish;
use mac_address::MacAddress;
use tonic::{Response, Status};

use crate::{
    api::{log_machine_id, log_request_data, Api},
    db::{self, DatabaseError},
    model::machine::machine_id::{try_parse_machine_id, MachineId},
    redfish::RedfishAuth,
    CarbideError,
};

async fn get_redfish_client(
    api: &Api,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
) -> Result<Box<dyn Redfish>, CarbideError> {
    log_machine_id(machine_id);
    let snapshot = db::managed_host::load_snapshot(txn, machine_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or(CarbideError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })?;

    if snapshot.instance.is_none() {
        return Err(CarbideError::GenericError(format!(
            "could not find instance with UUID: {}",
            machine_id
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
    let bmc_mac = snapshot
        .host_snapshot
        .bmc_info
        .mac
        .as_ref()
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "bmc_mac",
            id: machine_id.to_string(),
        })?;

    let bmc_mac_address = bmc_mac.parse::<MacAddress>().map_err(CarbideError::from)?;

    api.redfish_pool
        .create_client(
            bmc_ip,
            snapshot.host_snapshot.bmc_info.port,
            RedfishAuth::Key(CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
            }),
            true,
        )
        .await
        .map_err(|e| CarbideError::GenericError(e.to_string()))
}

pub(crate) async fn redfish_power_control(
    api: &Api,
    request: tonic::Request<rpc::RedfishPowerControlRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin force_reboot_host",
            e,
        ))
    })?;

    let req = request.into_inner();
    let request_machine_id = req.machine_id.clone().unwrap_or_default();
    let machine_id = try_parse_machine_id(&request_machine_id).map_err(CarbideError::from)?;
    log_machine_id(&machine_id);

    let client = get_redfish_client(api, &mut txn, &machine_id).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit force_reboot_host",
            e,
        ))
    })?;

    let action = match req.action() {
        rpc::redfish_power_control_request::SystemPowerControl::On => {
            libredfish::SystemPowerControl::On
        }
        rpc::redfish_power_control_request::SystemPowerControl::GracefulShutdown => {
            libredfish::SystemPowerControl::GracefulShutdown
        }
        rpc::redfish_power_control_request::SystemPowerControl::ForceOff => {
            libredfish::SystemPowerControl::ForceOff
        }
        rpc::redfish_power_control_request::SystemPowerControl::GracefulRestart => {
            libredfish::SystemPowerControl::GracefulRestart
        }
        rpc::redfish_power_control_request::SystemPowerControl::ForceRestart => {
            libredfish::SystemPowerControl::ForceRestart
        }
    };

    client.power(action).await.map_err(|e| {
        CarbideError::GenericError(format!("Failed redfish ForceRestart subtask: {}", e))
    })?;

    Ok(Response::new(()))
}

pub(crate) async fn get_redfish_job_state(
    api: &Api,
    request: tonic::Request<rpc::GetRedfishJobStateRequest>,
) -> Result<Response<rpc::GetRedfishJobStateResponse>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin poll_redfish_job",
            e,
        ))
    })?;

    let req = request.into_inner();
    let machine_id =
        try_parse_machine_id(&req.machine_id.unwrap_or_default()).map_err(CarbideError::from)?;
    log_machine_id(&machine_id);

    let client = get_redfish_client(api, &mut txn, &machine_id).await?;

    let job_state = match client
        .get_job_state(&req.job_id)
        .await
        .map_err(CarbideError::from)?
    {
        libredfish::JobState::Scheduled => {
            ::rpc::forge::get_redfish_job_state_response::RedfishJobState::Scheduled
        }
        libredfish::JobState::Running => {
            ::rpc::forge::get_redfish_job_state_response::RedfishJobState::Running
        }
        libredfish::JobState::Completed => {
            ::rpc::forge::get_redfish_job_state_response::RedfishJobState::Completed
        }
        libredfish::JobState::CompletedWithErrors => {
            ::rpc::forge::get_redfish_job_state_response::RedfishJobState::CompletedWithErrors
        }
        libredfish::JobState::Unknown => {
            ::rpc::forge::get_redfish_job_state_response::RedfishJobState::Unknown
        }
    };

    Ok(Response::new(rpc::GetRedfishJobStateResponse {
        job_state: job_state.into(),
    }))
}
