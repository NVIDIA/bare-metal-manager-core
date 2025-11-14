use ::rpc::common::MachineIdList;
use ::rpc::forge::{self as rpc, AttestationResponse};
use config_version::ConfigVersion;
use db::attestation::spdm::insert_or_update_machine_attestation_request;
use itertools::Itertools;
use model::attestation::spdm::SpdmMachineAttestation;
use tonic::{Request, Response, Status};

use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

pub(crate) async fn trigger_machine_attestation(
    api: &Api,
    request: Request<rpc::AttestationData>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let request = request.get_ref();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    let mut txn = api.txn_begin("trigger_machine_attestation").await?;
    let attestation_request = SpdmMachineAttestation {
        machine_id,
        requested_at: chrono::Utc::now(),
        started_at: None,
        canceled_at: None,
        state: model::attestation::spdm::AttestationState::CheckIfAttestationSupported,
        state_version: ConfigVersion::initial(),
        state_outcome: None,
        attestation_status: model::attestation::spdm::SpdmAttestationStatus::NotStarted,
    };
    insert_or_update_machine_attestation_request(&mut txn, &attestation_request).await?;
    txn.commit().await?;

    Ok(Response::new(()))
}

pub(crate) async fn cancel_machine_attestation(
    api: &Api,
    request: Request<rpc::AttestationData>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let request = request.get_ref();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    let mut txn = api.txn_begin("trigger_cancel_machine_attestation").await?;
    db::attestation::spdm::cancel_machine_attestation(&mut txn, &machine_id).await?;
    txn.commit().await?;

    Ok(Response::new(()))
}

pub(crate) async fn list_machine_ids_under_attestation(
    api: &Api,
    _request: Request<rpc::AttestationIdsRequest>,
) -> Result<Response<MachineIdList>, Status> {
    log_request_data(&_request);

    let mut txn = api.txn_begin("trigger_list_machine_attestation").await?;
    let machine_ids = db::attestation::spdm::find_machine_ids(&mut txn).await?;
    txn.commit().await?;

    Ok(Response::new(MachineIdList { machine_ids }))
}

pub(crate) async fn list_machines_under_attestation(
    api: &Api,
    request: Request<rpc::AttestationMachineList>,
) -> Result<Response<AttestationResponse>, Status> {
    log_request_data(&request);
    let request = request.get_ref();

    let mut txn = api.txn_begin("trigger_list_machine_attestation").await?;
    let snapshot =
        db::attestation::spdm::load_snapshot_for_machine_ids(&mut txn, &request.machine_ids)
            .await?;
    txn.commit().await?;

    Ok(Response::new(AttestationResponse {
        machines: snapshot.iter().map(|x| x.clone().into()).collect_vec(),
    }))
}
