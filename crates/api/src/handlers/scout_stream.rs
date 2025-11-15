/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::protos::forge as rpc;
use tonic::{Request, Response, Status};

use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

pub async fn show_connections(
    api: &Api,
    request: Request<rpc::ScoutStreamShowConnectionsRequest>,
) -> Result<Response<rpc::ScoutStreamShowConnectionsResponse>, Status> {
    log_request_data(&request);

    let connections = api.scout_stream_registry.list_connected().await;

    let connection_list = connections
        .into_iter()
        .map(|(machine_id, connected_at)| {
            let duration = connected_at
                .elapsed()
                .unwrap_or(std::time::Duration::from_secs(0));

            rpc::ScoutStreamConnectionInfo {
                machine_id: machine_id.into(),
                connected_at: format_system_time(connected_at),
                uptime_seconds: duration.as_secs(),
            }
        })
        .collect();

    Ok(Response::new(rpc::ScoutStreamShowConnectionsResponse {
        scout_stream_connections: connection_list,
    }))
}
pub async fn disconnect(
    api: &Api,
    request: Request<rpc::ScoutStreamDisconnectRequest>,
) -> Result<Response<rpc::ScoutStreamDisconnectResponse>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;
    let success = api.scout_stream_registry.unregister(machine_id).await;
    Ok(Response::new(rpc::ScoutStreamDisconnectResponse {
        machine_id: machine_id.into(),
        success,
    }))
}

pub async fn ping(
    api: &Api,
    request: Request<rpc::ScoutStreamAdminPingRequest>,
) -> Result<Response<rpc::ScoutStreamAdminPingResponse>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    // Check if the machine is connected.
    if !api.scout_stream_registry.is_connected(machine_id).await {
        return Err(Status::not_found(format!(
            "scout agent on machine is not connected: {machine_id}"
        )));
    }

    let request = rpc::ScoutStreamScoutBoundMessage::new_flow(
        rpc::scout_stream_scout_bound_message::Payload::ScoutStreamAgentPingRequest(
            rpc::ScoutStreamAgentPingRequest {},
        ),
    );

    let response = api
        .scout_stream_registry
        .send_request(machine_id, request)
        .await
        .map_err(|status| {
            Status::new(
                status.code(),
                format!(
                    "error while attempting to send ping request to scout: {}",
                    status.message()
                ),
            )
        })?;

    match response.payload {
        Some(rpc::scout_stream_api_bound_message::Payload::ScoutStreamAgentPingResponse(
            agent_ping_response,
        )) => match agent_ping_response.reply {
            Some(rpc::scout_stream_agent_ping_response::Reply::Pong(pong)) => {
                Ok(Response::new(rpc::ScoutStreamAdminPingResponse { pong }))
            }
            Some(rpc::scout_stream_agent_ping_response::Reply::Error(error)) => {
                Err(Status::internal(format!(
                    "scout agent returned error attempting to ping agent (machine_id={machine_id}): {}",
                    error.message
                )))
            }
            None => Err(Status::internal(format!(
                "scout agent returned empty ping reply (machine_id={machine_id})"
            ))),
        },
        _ => Err(Status::internal(format!(
            "unexpected response type from scout agent for ping response (machine_id={machine_id})"
        ))),
    }
}

// format_system_time formats a SystemTime as an RFC3339 string.
fn format_system_time(time: std::time::SystemTime) -> String {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            chrono::DateTime::from_timestamp(secs as i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "unknown".to_string())
        }
        Err(_) => "unknown".to_string(),
    }
}
