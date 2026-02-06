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

// scout_stream.rs
// This module contains code related to managing scout agent connections.
// It includes the AgentConnection type, which holds the channels used for
// streaming communication, and the ConnectionRegistry, which contains a map
// of machine_id to AgentConnection along with an interface to send messages
// through it.

use std::collections::HashMap;
use std::sync::Arc;

use ::rpc::protos::forge::{ScoutStreamApiBoundMessage, ScoutStreamScoutBoundMessage};
use carbide_uuid::machine::MachineId;
use tokio::sync::{RwLock, mpsc, oneshot};
use tonic::Status;

// AgentConnection represents an active streaming connection to
// a scout agent. It contains the corresponding machine_id, the
// channels used to pass messages, and any additional metadata
// that we'd like.
struct AgentConnection {
    // machine_id is the identifier for this agent's machine.
    machine_id: MachineId,
    // connected_at is when this connection was established.
    connected_at: std::time::SystemTime,
    // flows are the active request/response flows currently
    // in flight over this connection.
    // tx is the sender for sending requests to the scout agent.
    tx: mpsc::Sender<Result<ScoutStreamScoutBoundMessage, Status>>,
    // rx is the receiver for getting responses from the scout agent.
    rx: Arc<RwLock<mpsc::Receiver<ScoutStreamApiBoundMessage>>>,
    flows: Arc<RwLock<HashMap<uuid::Uuid, oneshot::Sender<ScoutStreamApiBoundMessage>>>>,
}

// ConnectionRegistry is the interface for working with active
// scout agent connections. It maintains a map of machine ID
// to the AgentConnection, and exposes an interface to show
// current connections and send messages across them.
#[derive(Clone)]
pub struct ConnectionRegistry {
    // connections is used to map a machine_id to a scout
    // agent connection.
    connections: Arc<RwLock<HashMap<MachineId, AgentConnection>>>,
}

impl ConnectionRegistry {
    // new creates a new connection registry.
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // register adds a new scout agent connection to the registry,
    // provisioning data structures necessary for tracking the machine,
    // its singular connection, and active flows over the connection.
    pub async fn register(
        &self,
        machine_id: MachineId,
        tx: mpsc::Sender<Result<ScoutStreamScoutBoundMessage, Status>>,
        rx: mpsc::Receiver<ScoutStreamApiBoundMessage>,
    ) {
        let connection = AgentConnection {
            machine_id,
            connected_at: std::time::SystemTime::now(),
            tx,
            rx: Arc::new(RwLock::new(rx)),
            flows: Arc::new(RwLock::new(HashMap::new())),
        };

        // And now background a connection-specific receiver whose job it
        // is to receive messages over the singular connection channel
        // and map the embedded message flow_uuid to an underlying oneshot
        // flow channel.
        let connection_flows = Arc::clone(&connection.flows);
        let connection_rx = Arc::clone(&connection.rx);
        tokio::spawn(async move {
            loop {
                let response = {
                    let mut rx_guard = connection_rx.write().await;
                    rx_guard.recv().await
                };

                let Some(response) = response else {
                    tracing::info!("scout agent connection closed (machine_id={machine_id})");
                    break;
                };

                // Extract and validate flow_uuid.
                let flow_uuid = match extract_flow_uuid(&response, machine_id) {
                    Ok(uuid) => uuid,
                    Err(_) => continue,
                };

                // Route response to the waiting flow.
                let mut flows = connection_flows.write().await;
                if let Some(sender) = flows.remove(&flow_uuid) {
                    if let Err(send_err) = sender.send(response) {
                        tracing::warn!(
                            "error relaying flow response (machine_id={machine_id}, flow_uuid={flow_uuid}): {send_err:?}"
                        );
                    }
                } else {
                    tracing::warn!(
                        "dropping flow response for unknown flow_uuid (machine_id={machine_id}, flow_uuid={flow_uuid}): {response:?}"
                    );
                }
            }
        });

        let mut connections = self.connections.write().await;
        connections.insert(machine_id, connection);
        tracing::info!("registered scout agent connection for machine: {machine_id}");
    }

    // unregister removes a scout agent connection from the registry.
    pub async fn unregister(&self, machine_id: MachineId) -> bool {
        let mut connections = self.connections.write().await;
        if connections.remove(&machine_id).is_some() {
            tracing::info!("unregistered scout agent connection for machine: {machine_id}");
            true
        } else {
            tracing::info!(
                "could not unregister scout agent connection for machine (not found): {machine_id}"
            );
            false
        }
    }

    // send_request sends a request to a scout agent and waits for a response.
    pub async fn send_request(
        &self,
        machine_id: MachineId,
        request: ScoutStreamScoutBoundMessage,
    ) -> Result<ScoutStreamApiBoundMessage, Status> {
        let Some(flow_uuid_pb) = request.flow_uuid.as_ref() else {
            return Err(Status::internal(format!(
                "flow_uuid empty for flow with {machine_id}, unable to build flow",
            )));
        };

        let flow_uuid: uuid::Uuid = match flow_uuid_pb.clone().try_into() {
            Ok(flow_uuid) => flow_uuid,
            Err(e) => {
                return Err(Status::internal(format!(
                    "failed to decode flow_uuid (machine_id={machine_id}): {flow_uuid_pb:?}: {e:?}",
                )));
            }
        };

        let (connection_tx, connection_flows) = {
            let connections = self.connections.read().await;
            let connection = connections.get(&machine_id).ok_or_else(|| {
                Status::not_found(format!(
                    "machine not connected to a scout stream: {machine_id}"
                ))
            })?;
            (connection.tx.clone(), Arc::clone(&connection.flows))
        };

        // Now create the oneshot channel flow specific
        // to this request/response flow. What happens is we create
        // the flow_uuid-associated send/recv channel here, then send
        // the request off through our connection channel. Next,
        // our connection message processor will map the flow_uuid
        // to the corresponding response_tx, push the message to it,
        // and then our response_rx will receive it here.
        let (response_tx, response_rx) = oneshot::channel();
        {
            let mut flows = connection_flows.write().await;
            flows.insert(flow_uuid, response_tx);
        }

        // And now the request to the scout agent.
        tracing::info!(
            "sending request to scout agent (machine_id={machine_id}, flow_uuid={flow_uuid})"
        );

        connection_tx.send(Ok(request)).await.map_err(|e| {
            Status::internal(format!(
                "failed to send request to scout agent (machine_id={machine_id}, flow_uuid={flow_uuid}): {e}"
            ))
        })?;

        // And now we wait for a response from the agent.
        // TODO(chet): This is where we'd put timeout handling.
        response_rx.await.map_err(|e| {
            Status::internal(format!(
                "response channel error (machine_id={machine_id}, flow_uuid={flow_uuid}): {e}",
            ))
        })
    }

    // is_connected checks if a machine is currently connected.
    pub async fn is_connected(&self, machine_id: MachineId) -> bool {
        let connections = self.connections.read().await;
        connections.contains_key(&machine_id)
    }

    // list_connected returns a list of all connected machines with connection info.
    pub async fn list_connected(&self) -> Vec<(MachineId, std::time::SystemTime)> {
        let connections = self.connections.read().await;
        connections
            .iter()
            .map(|(machine_id, conn)| {
                tracing::debug!("active scout stream connection: {}", conn.machine_id);
                (*machine_id, conn.connected_at)
            })
            .collect()
    }
}

// extract_flow_uuid is a little helper to extract and validate flow_uuid,
// logging warnings depending on things that happen.
fn extract_flow_uuid(
    response: &ScoutStreamApiBoundMessage,
    machine_id: MachineId,
) -> Result<uuid::Uuid, ()> {
    let flow_uuid_pb = response.flow_uuid.as_ref().ok_or_else(|| {
        tracing::warn!(
            "dropping flow response with empty flow_uuid (machine_id={machine_id}): {response:?}"
        );
    })?;

    flow_uuid_pb.clone().try_into().map_err(|e| {
        tracing::warn!(
            "failed to decode flow_uuid (machine_id={machine_id}): {flow_uuid_pb:?}: {e:?}"
        );
    })
}
