use std::collections::HashMap;

use chrono::{DateTime, Local};
use http::{HeaderMap, HeaderValue, Uri, header::CONTENT_TYPE, uri::Authority};
use sqlx::PgPool;
use utils::HostPortPair;

use crate::{
    CarbideError,
    api::log_request_data,
    auth::external_user_info,
    db::{
        DatabaseError,
        redfish_actions::{
            approve_request, delete_request, fetch_request, find_serials, insert_request,
            list_requests, set_applied, update_response,
        },
    },
    model::redfish::BMCResponse,
};

// TODO: put this in carbide config?
pub const NUM_REQUIRED_APPROVALS: usize = 2;

pub async fn redfish_browse(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishBrowseRequest>,
) -> Result<tonic::Response<::rpc::forge::RedfishBrowseResponse>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let uri: http::Uri = match request.uri.clone().parse() {
        Ok(uri) => uri,
        Err(err) => {
            return Err(CarbideError::internal(format!("Parsing uri failed: {err}")).into());
        }
    };

    let (metadata, new_uri, headers, http_client) = create_client(api, uri).await?;

    let response = match http_client
        .request(http::Method::GET, new_uri.to_string())
        .basic_auth(metadata.user.clone(), Some(metadata.password.clone()))
        .headers(headers)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return Err(CarbideError::internal(format!("Http request failed: {e:?}")).into());
        }
    };

    let headers = response
        .headers()
        .iter()
        .map(|(x, y)| {
            (
                x.to_string(),
                String::from_utf8_lossy(y.as_bytes()).to_string(),
            )
        })
        .collect::<HashMap<String, String>>();

    let status = response.status();
    let text = response.text().await.map_err(|e| {
        CarbideError::internal(format!(
            "Error reading response body: {e}, Status: {status}"
        ))
    })?;

    Ok(tonic::Response::new(::rpc::forge::RedfishBrowseResponse {
        text,
        headers,
    }))
}
pub async fn redfish_list_actions(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishListActionsRequest>,
) -> Result<tonic::Response<::rpc::forge::RedfishListActionsResponse>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let result = list_requests(api, request).await?;

    Ok(tonic::Response::new(
        rpc::forge::RedfishListActionsResponse {
            actions: result.into_iter().map(Into::into).collect(),
        },
    ))
}

pub async fn redfish_create_action(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishCreateActionRequest>,
) -> Result<tonic::Response<::rpc::forge::RedfishCreateActionResponse>, tonic::Status> {
    log_request_data(&request);

    let authored_by = external_user_info(&request)?.user.ok_or(
        CarbideError::ClientCertificateMissingInformation("external user name".to_string()),
    )?;

    let request = request.into_inner();

    const DB_TXN_NAME: &str = "create redfish action";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let ip_to_serial = find_serials(&request.ips, &mut txn).await?;
    let machine_ips: Vec<_> = ip_to_serial.keys().cloned().collect();
    // this is the neatest way I could think of splitting the iterator/map into two vecs
    // explicitly in the same order. could be a for loop instead.
    let serials: Vec<_> = machine_ips
        .iter()
        .map(|ip| ip_to_serial.get(ip).unwrap())
        .collect();

    let request_id = insert_request(authored_by, request, &mut txn, machine_ips, serials).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(tonic::Response::new(
        ::rpc::forge::RedfishCreateActionResponse { request_id },
    ))
}

pub async fn redfish_approve_action(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishActionId>,
) -> Result<tonic::Response<::rpc::forge::RedfishApproveActionResponse>, tonic::Status> {
    log_request_data(&request);

    let approver = external_user_info(&request)?.user.ok_or(
        CarbideError::ClientCertificateMissingInformation("external user name".to_string()),
    )?;

    let request = request.into_inner();

    const DB_TXN_NAME: &str = "approve redfish action";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;
    let action_request = fetch_request(request, &mut txn).await?;
    if action_request.approvers.contains(&approver) {
        return Err(
            CarbideError::InvalidArgument("user already approved request".to_owned()).into(),
        );
    }

    let is_approved = approve_request(approver, request, &mut txn).await?;
    if !is_approved {
        return Err(
            CarbideError::InvalidArgument("user already approved request".to_owned()).into(),
        );
    }
    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(tonic::Response::new(
        ::rpc::forge::RedfishApproveActionResponse {},
    ))
}

pub async fn redfish_apply_action(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishActionId>,
) -> Result<tonic::Response<::rpc::forge::RedfishApplyActionResponse>, tonic::Status> {
    log_request_data(&request);

    let applier = external_user_info(&request)?.user.ok_or(
        CarbideError::ClientCertificateMissingInformation("external user name".to_string()),
    )?;

    let request = request.into_inner();

    const DB_TXN_NAME: &str = "apply redfish action";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let action_request = fetch_request(request, &mut txn).await?;
    if action_request.applied_at.is_some() {
        return Err(CarbideError::InvalidArgument("action already applied".to_owned()).into());
    }

    if action_request.approvers.len() < NUM_REQUIRED_APPROVALS {
        return Err(CarbideError::InvalidArgument("insufficient approvals".to_owned()).into());
    }

    let ip_to_serial = find_serials(&action_request.machine_ips, &mut txn).await?;

    let is_applied = set_applied(applier, request, &mut txn).await?;
    if !is_applied {
        return Err(CarbideError::InvalidArgument("Request was already applied".to_owned()).into());
    }

    for (index, (machine_ip, original_serial)) in action_request
        .machine_ips
        .iter()
        .zip(action_request.board_serials)
        .enumerate()
    {
        // check that serial is the same.
        if ip_to_serial.get(machine_ip) != Some(&original_serial) {
            update_response_in_tx(&api.database_connection, request, index, BMCResponse {
                headers: HashMap::new(),
                status: "not executed".to_owned(),
                body: "machine serial did not match original serial at time of request creation. IP address was reused".to_owned(),
                completed_at: DateTime::from(Local::now()),
            }).await?;
            continue;
        }

        let uri = Uri::builder()
            .scheme("https")
            .authority(
                TryInto::<Authority>::try_into(machine_ip.to_string())
                    .map_err(|e| CarbideError::internal(format!("invalid machine ip {e}")))?,
            )
            .path_and_query(&action_request.target)
            .build()
            .map_err(|e| CarbideError::internal(format!("invalid uri {e}")))?;
        let (metadata, proxied_uri, mut headers, http_client) = create_client(api, uri).await?;
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let parameters = action_request.parameters.clone();
        // Reference counted pool.
        let pool = api.database_connection.clone();
        // Spawn off the task to send the request, open a transaction, and store the result.
        tokio::spawn(async move {
            let response =
                handle_request(parameters, metadata, proxied_uri, headers, http_client).await;
            // Enclosing function may have returned. Nowhere to return error to.
            _ = update_response_in_tx(&pool, request, index, response).await;
        });
    }

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(tonic::Response::new(
        ::rpc::forge::RedfishApplyActionResponse {},
    ))
}

async fn update_response_in_tx(
    pool: &PgPool,
    request: rpc::forge::RedfishActionId,
    index: usize,
    response: BMCResponse,
) -> Result<(), tonic::Status> {
    const DB_TXN_NAME: &str = "update redfish action response";
    let mut txn = pool
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;
    update_response(request, &mut txn, response, index).await?;
    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;
    Ok(())
}

async fn handle_request(
    parameters: String,
    metadata: rpc::forge::BmcMetaDataGetResponse,
    new_uri: Uri,
    headers: HeaderMap,
    http_client: reqwest::Client,
) -> BMCResponse {
    let response = match http_client
        .request(http::Method::POST, new_uri.to_string())
        .basic_auth(metadata.user.clone(), Some(metadata.password.clone()))
        .body(parameters)
        .headers(headers)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return BMCResponse {
                headers: HashMap::new(),
                status: e
                    .status()
                    .map(|s| s.to_string())
                    .unwrap_or("missing status".to_owned()),
                body: format!("Http request failed: {e}"),
                completed_at: DateTime::from(Local::now()),
            };
        }
    };
    let headers = response
        .headers()
        .iter()
        .map(|(x, y)| {
            (
                x.to_string(),
                String::from_utf8_lossy(y.as_bytes()).to_string(),
            )
        })
        .collect::<HashMap<String, String>>();
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| CarbideError::internal(format!("Error reading response body: {e}")))
        .unwrap_or("could not decode body as text".to_owned());

    BMCResponse {
        headers,
        status: status.to_string(),
        body,
        completed_at: DateTime::from(Local::now()),
    }
}

async fn create_client(
    api: &crate::api::Api,
    uri: http::Uri,
) -> Result<
    (
        rpc::forge::BmcMetaDataGetResponse,
        http::Uri,
        HeaderMap,
        reqwest::Client,
    ),
    tonic::Status,
> {
    let bmc_metadata_request = tonic::Request::new(rpc::forge::BmcMetaDataGetRequest {
        machine_id: None,
        bmc_endpoint_request: Some(rpc::forge::BmcEndpointRequest {
            ip_address: uri.host().map(|x| x.to_string()).unwrap_or_default(),
            mac_address: None,
        }),
        role: rpc::forge::UserRoles::Administrator.into(),
        request_type: rpc::forge::BmcRequestType::Ipmi.into(),
    });

    let metadata = crate::handlers::bmc_metadata::get(api, bmc_metadata_request)
        .await?
        .into_inner();

    let proxy_address = api.dynamic_settings.bmc_proxy.load();
    let (host, port, add_custom_header) = match proxy_address.as_ref() {
        // No override
        None => (metadata.ip.clone(), metadata.port, false),
        // Override the host and port
        Some(HostPortPair::HostAndPort(h, p)) => (h.to_string(), Some(*p as u32), true),
        // Only override the host
        Some(HostPortPair::HostOnly(h)) => (h.to_string(), metadata.port, true),
        // Only override the port
        Some(HostPortPair::PortOnly(p)) => (metadata.ip.clone(), Some(*p as u32), false),
    };
    let new_authority = if let Some(port) = port {
        http::uri::Authority::try_from(format!("{host}:{port}"))
            .map_err(|e| CarbideError::internal(format!("creating url {e}")))?
    } else {
        http::uri::Authority::try_from(host)
            .map_err(|e| CarbideError::internal(format!("creating url {e}")))?
    };
    let mut parts = uri.into_parts();
    parts.authority = Some(new_authority);
    let new_uri = http::Uri::from_parts(parts)
        .map_err(|e| CarbideError::internal(format!("invalid url parts {e}")))?;
    let mut headers = HeaderMap::new();
    if add_custom_header {
        headers.insert(
            "forwarded",
            format!("host={orig_host}", orig_host = metadata.ip)
                .parse()
                .unwrap(),
        );
    };
    let http_client = {
        let builder = reqwest::Client::builder();
        let builder = builder
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .connect_timeout(std::time::Duration::from_secs(5)) // Limit connections to 5 seconds
            .timeout(std::time::Duration::from_secs(60)); // Limit the overall request to 60 seconds

        match builder.build() {
            Ok(client) => client,
            Err(err) => {
                tracing::error!(%err, "build_http_client");
                return Err(CarbideError::internal(format!("Http building failed: {err}")).into());
            }
        }
    };
    Ok((metadata, new_uri, headers, http_client))
}

pub async fn redfish_cancel_action(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishActionId>,
) -> Result<tonic::Response<::rpc::forge::RedfishCancelActionResponse>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();

    const DB_TXN_NAME: &str = "update redfish action response";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    delete_request(request, &mut txn).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(tonic::Response::new(
        ::rpc::forge::RedfishCancelActionResponse {},
    ))
}
