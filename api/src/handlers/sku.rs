use crate::{
    CarbideError, CarbideResult,
    api::{Api, log_request_data},
    db::{
        self, DatabaseError,
        machine::{MachineSearchConfig, find_machine_ids_by_sku_id},
    },
    handlers::utils::convert_and_log_machine_id,
    model::{
        machine::{BomValidating, ManagedHostState},
        sku::Sku,
    },
};

use chrono::Utc;
use rpc::forge::SkuIdList;
use tonic::{Request, Response};

pub(crate) async fn create(
    api: &Api,
    request: Request<::rpc::forge::SkuList>,
) -> CarbideResult<Response<::rpc::forge::SkuIdList>> {
    log_request_data(&request);
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin generate_sku_from_machine",
            e,
        ))
    })?;

    let sku_list = request.into_inner();

    let mut sku_ids = SkuIdList::default();

    for sku in sku_list.skus {
        let sku: Sku = sku.into();
        crate::db::sku::create(&mut txn, &sku).await?;
        sku_ids.ids.push(sku.id);
    }

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "commit sku create", e))
    })?;

    Ok(Response::new(sku_ids))
}

pub(crate) async fn delete(api: &Api, request: Request<SkuIdList>) -> CarbideResult<Response<()>> {
    log_request_data(&request);
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "begin delete_sku", e))
    })?;

    let sku_id_list = request.into_inner().ids;
    let mut skus = crate::db::sku::find(&mut txn, &sku_id_list).await?;

    let Some(sku) = skus.pop() else {
        return Err(CarbideError::InvalidArgument(format!(
            "The SKU {} does not exist",
            sku_id_list
                .first()
                .map(|id| id.to_string())
                .unwrap_or_default()
        )));
    };
    if !skus.is_empty() {
        return Err(CarbideError::NotImplemented);
    }

    let machine_ids = crate::db::machine::find_machine_ids_by_sku_id(&mut txn, &sku.id).await?;
    if !machine_ids.is_empty() {
        return Err(CarbideError::InvalidArgument(format!(
            "The SKUs are in use by {} machines",
            machine_ids.len()
        )));
    }

    crate::db::sku::delete(&mut txn, &sku.id).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "commit sku create", e))
    })?;

    Ok(Response::new(()))
}

pub(crate) async fn generate_from_machine(
    api: &Api,
    request: Request<::rpc::common::MachineId>,
) -> CarbideResult<Response<::rpc::forge::Sku>> {
    log_request_data(&request);
    let machine_id = convert_and_log_machine_id(Some(&request.into_inner()))?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin generate_sku_from_machine",
            e,
        ))
    })?;

    let sku = crate::db::sku::generate_sku_from_machine(&mut txn, &machine_id)
        .await
        .map_err(CarbideError::from)?;

    Ok(Response::new(sku.into()))
}

pub(crate) async fn assign_to_machine(
    api: &Api,
    request: Request<::rpc::forge::SkuMachinePair>,
) -> CarbideResult<Response<()>> {
    log_request_data(&request);
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin assign_sku_to_machine",
            e,
        ))
    })?;

    let sku_machine_pair = request.into_inner();
    let machine_id = convert_and_log_machine_id(sku_machine_pair.machine_id.as_ref())?;

    let machine =
        db::machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default()).await?;

    let machine = machine.ok_or(CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    match machine.current_state() {
        ManagedHostState::BomValidating {
            bom_validating_state: BomValidating::WaitingForSkuAssignment(_),
        } => {}
        ManagedHostState::Ready if machine.hw_sku.is_none() => {
            // if the host is in ready state without a sku, allow the assignment, but force a verification.
            // this can happen when 'ignore_unassigned_machines' is true
            crate::db::machine::update_sku_status_verify_request_time(&mut txn, &machine_id)
                .await?;
        }
        _ => {
            return Err(CarbideError::FailedPrecondition(
                "Specified machine is not in a valid state for assigning a SKU".to_string(),
            ));
        }
    }

    let mut skus = crate::db::sku::find(&mut txn, &[sku_machine_pair.sku_id.clone()]).await?;

    let sku = skus.pop().ok_or(CarbideError::NotFoundError {
        kind: "SKU ID",
        id: sku_machine_pair.sku_id.clone(),
    })?;

    if !skus.is_empty() {
        return Err(CarbideError::internal(format!(
            "Unexpected additional SKUs found for ID: {}",
            sku_machine_pair.sku_id.clone()
        )));
    }

    crate::db::machine::assign_sku(&mut txn, &machine_id, &sku.id)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "assign to machine", e))
    })?;

    Ok(Response::new(()))
}

pub(crate) async fn verify_for_machine(
    api: &Api,
    request: Request<::rpc::common::MachineId>,
) -> CarbideResult<Response<()>> {
    log_request_data(&request);
    let machine_id = convert_and_log_machine_id(Some(&request.into_inner()))?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin verify_sku_for_machine",
            e,
        ))
    })?;

    let machine = db::machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default())
        .await
        .map_err(CarbideError::from)?;

    let machine = machine.ok_or(CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    match machine.current_state() {
        ManagedHostState::Ready
        | ManagedHostState::BomValidating {
            bom_validating_state: BomValidating::SkuVerificationFailed(_),
        } => {}
        _ => {
            return Err(CarbideError::FailedPrecondition(
                "Specified machine is not in a valid state for machine SKU verification"
                    .to_string(),
            ));
        }
    }

    let mut sku_status = machine.hw_sku_status.unwrap_or_default();

    sku_status.verify_request_time = Some(Utc::now());

    crate::db::machine::update_sku_status_verify_request_time(&mut txn, &machine_id)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "verify machine with sku",
            e,
        ))
    })?;

    Ok(Response::new(()))
}

pub(crate) async fn remove_sku_association(
    api: &Api,
    request: Request<::rpc::common::MachineId>,
) -> CarbideResult<Response<()>> {
    log_request_data(&request);
    let machine_id = convert_and_log_machine_id(Some(&request.into_inner()))?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin remove_sku_association",
            e,
        ))
    })?;

    let machine = db::machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default())
        .await
        .map_err(CarbideError::from)?;

    let machine = machine.ok_or(CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    match machine.current_state() {
        ManagedHostState::Ready
        | ManagedHostState::BomValidating {
            bom_validating_state: BomValidating::SkuVerificationFailed(_),
        } => {}
        _ => {
            return Err(CarbideError::FailedPrecondition(
                "Specified machine is not in a valid state for removing SKU association"
                    .to_string(),
            ));
        }
    }

    crate::db::machine::unassign_sku(&mut txn, &machine_id)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "remove sku association",
            e,
        ))
    })?;

    Ok(Response::new(()))
}

pub(crate) async fn get_all_ids(
    api: &Api,
    request: Request<()>,
) -> CarbideResult<Response<::rpc::forge::SkuIdList>> {
    log_request_data(&request);
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_all_sku_ids",
            e,
        ))
    })?;

    let sku_ids = crate::db::sku::get_sku_ids(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    Ok(Response::new(::rpc::forge::SkuIdList {
        ids: sku_ids.into_iter().collect(),
    }))
}

pub(crate) async fn find_skus_by_ids(
    api: &Api,
    request: Request<::rpc::forge::SkusByIdsRequest>,
) -> CarbideResult<Response<::rpc::forge::SkuList>> {
    log_request_data(&request);

    let sku_ids = request.into_inner().ids;
    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if sku_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        )));
    } else if sku_ids.is_empty() {
        return Err(CarbideError::InvalidArgument(
            "at least one ID must be provided".to_string(),
        ));
    }

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_skus_by_ids",
            e,
        ))
    })?;

    let skus = crate::db::sku::find(&mut txn, &sku_ids).await?;

    let mut rpc_skus: Vec<rpc::forge::Sku> =
        skus.into_iter().map(std::convert::Into::into).collect();

    for rpc_sku in rpc_skus.iter_mut() {
        rpc_sku.associated_machine_ids = find_machine_ids_by_sku_id(&mut txn, &rpc_sku.id)
            .await?
            .into_iter()
            .map(std::convert::Into::into)
            .collect();
    }

    Ok(Response::new(rpc::forge::SkuList { skus: rpc_skus }))
}

pub(crate) async fn update_sku_metadata(
    api: &Api,
    request: Request<::rpc::forge::SkuUpdateMetadataRequest>,
) -> CarbideResult<Response<()>> {
    log_request_data(&request);

    let request = request.into_inner();

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_skus_by_ids",
            e,
        ))
    })?;

    crate::db::sku::update_metadata(
        &mut txn,
        request.sku_id,
        request.description,
        request.device_type,
    )
    .await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "remove sku association",
            e,
        ))
    })?;

    Ok(Response::new(()))
}

pub(crate) async fn replace_sku_components(
    api: &Api,
    request: Request<::rpc::forge::SkuReplaceComponentsRequest>,
) -> CarbideResult<Response<rpc::forge::Sku>> {
    let request = request.into_inner();
    let Some(components) = request.components else {
        return Err(CarbideError::InvalidArgument(
            "Components is required".to_string(),
        ));
    };

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_skus_by_ids",
            e,
        ))
    })?;

    let sku = crate::db::sku::replace_components(&mut txn, &request.id, components.into()).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "remove sku association",
            e,
        ))
    })?;

    Ok(Response::new(sku.into()))
}
