/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use ::rpc::protos::forge as rpc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::api::{Api, ScoutStreamType, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

// scout_stream handles the bidirectional streaming connection from scout agents.
// scout agents call scout_stream and send an Init message, and then carbide-api
// will send down "request" messages to connected agent(s) to either instruct them
// or ask them for information (sometimes for state changes, other times for
// feeding data back to administrative CLI/UI calls).
pub(crate) async fn scout_stream(
    api: &Api,
    request: Request<Streaming<rpc::ScoutStreamApiBoundMessage>>,
) -> Result<Response<ScoutStreamType>, Status> {
    log_request_data(&request);

    let mut stream = request.into_inner();

    let init_message = stream
        .message()
        .await?
        .ok_or_else(|| Status::invalid_argument("invalid message received"))?;

    // As part of "constructing" the new scout stream, we expect
    // an Init message as the first thing from the client (in this
    // case, a scout agent).
    let machine_id = match init_message.payload {
        Some(rpc::scout_stream_api_bound_message::Payload::Init(init)) => {
            convert_and_log_machine_id(init.machine_id.as_ref())?
        }
        _ => {
            return Err(Status::invalid_argument(
                "first ScoutStream client message must be an Init message",
            ));
        }
    };

    tracing::info!("scout agent connected for machine: {machine_id}");

    // Now we create channels for bidirectional communication. The API
    // will receive on one side, process whatever is packed into the oneof field
    // for the stream message, and then pass it off out the other side.
    let (agent_tx, agent_rx) = mpsc::channel::<rpc::ScoutStreamApiBoundMessage>(100);
    let (server_tx, server_rx) =
        mpsc::channel::<Result<rpc::ScoutStreamScoutBoundMessage, Status>>(100);

    // Next, register the connection using the machine ID and our fancy new channels.
    api.scout_stream_registry
        .register(machine_id, server_tx.clone(), agent_rx)
        .await;

    // And now spawn a task to forward agent messages through
    // the connection registry.
    let registry_clone = api.scout_stream_registry.clone();
    tokio::spawn(async move {
        while let Ok(Some(message)) = stream.message().await {
            if agent_tx.send(message).await.is_err() {
                tracing::error!("failed to forward message received from scout agent");
                break;
            }
        }

        // If/when the connection breaks, unregister the scout
        // agent connection from the connection registry.
        tracing::info!("scout agent disconnected for machine: {machine_id}");
        registry_clone.unregister(machine_id).await;
    });

    // Ok(Response::new(ReceiverStream::new(server_rx)))
    Ok(Response::new(Box::pin(ReceiverStream::new(server_rx))))
}

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
