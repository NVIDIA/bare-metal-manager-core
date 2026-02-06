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

use std::sync::Arc;

use config::Config;
use eyre::{Report, WrapErr};
use pdns::request::PdnsRequest;
use pdns::response::PdnsResponse;
use pdns::socket::PdnsSocket;
use rpc::JsonDnsResourceRecord;
use rpc::forge_tls_client::{ApiConfig, ForgeClientT, ForgeTlsClient};
use rpc::protos::dns::{
    DnsResourceRecordLookupRequest, DomainMetadataRequest, GetAllDomainsRequest,
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use uuid::Uuid;

pub mod config;
pub mod legacy;
pub mod pdns;

#[derive(Debug, Clone)]
pub struct MethodParseError;

pub async fn start(config: Config) -> Result<(), eyre::Report> {
    let config = Arc::new(config);

    let forge_client_config = config.clone().forge_client_config();
    let api_uri = config.carbide_uri.to_string();
    let api_config = ApiConfig::new(api_uri.as_str(), &forge_client_config);

    let client = Arc::new(Mutex::new(ForgeTlsClient::retry_build(&api_config).await?));

    let socket = PdnsSocket::new_socket(config.clone())?;
    let listener = socket.socket.clone();

    loop {
        let listener = listener.lock().await;

        if let Ok((stream, _)) = listener.accept().await {
            let client = client.clone();
            let conn_id = Uuid::new_v4();
            tokio::spawn(async move {
                let span = tracing::info_span!("connection", %conn_id);
                let _guard = span.enter();

                tracing::info!("Connection accepted");
                if let Err(err) = handle_connection(stream, client).await {
                    tracing::error!(
                        error = ?err,
                        "Connection handling failed"
                    );
                }
            });
        }
    }
}
async fn handle_connection(
    mut stream: UnixStream,
    client: Arc<Mutex<ForgeClientT>>,
) -> Result<(), Report> {
    let (reader, mut writer) = stream.split();

    let mut reader = BufReader::new(reader);
    let mut buffer = String::new();

    while reader.read_line(&mut buffer).await? > 0 {
        let request_id = Uuid::new_v4();

        let req: PdnsRequest = serde_json::from_str(buffer.as_str()).map_err(|e| {
            tracing::error!(
                raw_request = %buffer.trim(),
                error = %e,
                "Failed to parse PDNS request"
            );
            e
        })?;

        let span = tracing::info_span!("pdns_request", %request_id, method = %req.method);
        let _guard = span.enter();

        tracing::debug!(
            params = ?req.parameters,
            "Received PDNS request"
        );

        let start = std::time::Instant::now();
        let response = match req.method.as_str() {
            "getAllDomains" => {
                match handle_get_all_domains(&req, &client).await {
                    Ok(response) => response,
                    Err(e) => {
                        tracing::error!(
                            method = "getAllDomains",
                            error = %e,
                            "Failed to process getAllDomains - returning empty result to PowerDNS"
                        );
                        // Return empty result to PowerDNS instead of closing connection
                        PdnsResponse::from(Vec::<Value>::new())
                    }
                }
            }

            "getAllDomainMetadata" => {
                match handle_get_all_domain_metadata(&req, &client).await {
                    Ok(response) => response,
                    Err(e) => {
                        tracing::error!(
                            method = "getAllDomainMetadata",
                            error = %e,
                            "Failed to process getAllDomainMetadata - returning empty result to PowerDNS"
                        );
                        // Return empty result to PowerDNS instead of closing connection
                        PdnsResponse::from(Vec::<Value>::new())
                    }
                }
            }

            "lookup" => {
                match handle_lookup(&req, &client).await {
                    Ok(response) => response,
                    Err(e) => {
                        tracing::error!(
                            method = "lookup",
                            error = %e,
                            "Failed to process lookup - returning empty result to PowerDNS"
                        );
                        // Return empty result to PowerDNS instead of closing connection
                        PdnsResponse::from(Vec::<Value>::new())
                    }
                }
            }
            "initialize" => {
                let span = tracing::info_span!("initialize");
                let _guard = span.enter();

                tracing::info!(method = "initialize", "Processing initialize request");
                PdnsResponse::new(json!({"result": true}))
            }
            _ => {
                let span = tracing::warn_span!("unknown_method", method = %req.method);
                let _guard = span.enter();

                tracing::warn!(
                    method = %req.method,
                    parameters = ?req.parameters,
                    "Unknown RPC method received"
                );
                PdnsResponse::new(
                    json!({"result": false, "log": ["Unknown method: {} called", req.method]}),
                )
            }
        };

        let duration = start.elapsed();
        tracing::debug!(
            method = %req.method,
            duration_ms = duration.as_millis(),
            "Request completed"
        );

        send_response(&mut writer, response).await?;
        buffer.clear();
    }

    Ok(())
}

async fn handle_get_all_domains(
    req: &PdnsRequest,
    client: &Arc<Mutex<ForgeClientT>>,
) -> Result<PdnsResponse, Report> {
    let query: GetAllDomainsRequest = req.try_into()?;
    let span = tracing::info_span!("get_all_domains");
    let _guard = span.enter();

    tracing::info!(method = "getAllDomains", "Processing getAllDomains request");

    let api_start = std::time::Instant::now();
    let mut client = client.lock().await;
    let domains = client.get_all_domains(query).await?.into_inner();
    let api_duration = api_start.elapsed();

    let res = domains
        .result
        .into_iter()
        .map(|x| serde_json::to_value(x).unwrap_or_default())
        .collect::<Vec<_>>();

    tracing::info!(
        method = "getAllDomains",
        domain_count = res.len(),
        duration_ms = api_duration.as_millis(),
        "getAllDomains completed"
    );

    let response = PdnsResponse::from(res);
    tracing::trace!(
        method = "getAllDomains",
        response = ?response,
        "Sending response"
    );
    Ok(response)
}

async fn handle_get_all_domain_metadata(
    req: &PdnsRequest,
    client: &Arc<Mutex<ForgeClientT>>,
) -> Result<PdnsResponse, Report> {
    let query: DomainMetadataRequest = req.try_into()?;
    let span = tracing::info_span!("get_all_domain_metadata", domain = %query.domain);
    let _guard = span.enter();

    tracing::info!(
        method = "getAllDomainMetadata",
        domain = %query.domain,
        "Processing getAllDomainMetadata request"
    );

    let api_start = std::time::Instant::now();
    let mut client = client.lock().await;
    let metadata = client.get_all_domain_metadata(query).await?.into_inner();
    let api_duration = api_start.elapsed();

    let res = metadata
        .result
        .into_iter()
        .map(|x| serde_json::to_value(x).unwrap_or_default())
        .collect::<Vec<_>>();

    tracing::info!(
        method = "getAllDomainMetadata",
        metadata_count = res.len(),
        duration_ms = api_duration.as_millis(),
        "getAllDomainMetadata completed"
    );

    let response = PdnsResponse::from(res);
    tracing::trace!(
        method = "getAllDomainMetadata",
        response = ?response,
        "Sending response"
    );
    Ok(response)
}

async fn handle_lookup(
    req: &PdnsRequest,
    client: &Arc<Mutex<ForgeClientT>>,
) -> Result<PdnsResponse, Report> {
    let query: DnsResourceRecordLookupRequest = req.try_into()?;

    // Create a dedicated span for DNS lookup with all query parameters for correlation
    // This enables correlation with PowerDNS logs via qname, qtype, remote, and timestamp
    let lookup_span = tracing::info_span!(
        "dns_lookup",
        qname = %query.qname,
        qtype = %query.qtype,
        zone_id = %query.zone_id,
        remote = %query.remote.as_deref().unwrap_or("unknown"),
        real_remote = %query.real_remote.as_deref().unwrap_or("unknown"),
        local = %query.local.as_deref().unwrap_or("unknown"),
    );
    let _lookup_guard = lookup_span.enter();

    tracing::info!(method = "lookup", "Processing DNS lookup request");

    let lookup_start = std::time::Instant::now();
    let mut client = client.lock().await;
    let record_lookup_response = client.lookup_record(query.clone()).await?.into_inner();
    let lookup_duration = lookup_start.elapsed();

    tracing::info!(
        method = "lookup",
        record_count = record_lookup_response.records.len(),
        duration_ms = lookup_duration.as_millis(),
        "DNS lookup completed"
    );

    let value = record_lookup_response
        .records
        .into_iter()
        .map(|x| Value::from(JsonDnsResourceRecord(x)))
        .collect::<Vec<_>>();

    let response = PdnsResponse::from(value);
    tracing::trace!(
        method = "lookup",
        response = ?response,
        "Sending response"
    );
    Ok(response)
}

async fn send_response(
    writer: &mut tokio::net::unix::WriteHalf<'_>,
    response: PdnsResponse,
) -> Result<(), Report> {
    // Serialize the response into a JSON string
    let response_str = serde_json::to_string(&response)
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "Failed to serialize response"
            );
            e
        })
        .wrap_err("Failed to serialize response")?;

    let span = tracing::debug_span!("send_response", response_size = response_str.len());
    let _guard = span.enter();

    let mut bytes = response_str.as_bytes();

    // Track the total bytes written
    let mut total_written = 0;

    // Write all bytes in a loop
    while !bytes.is_empty() {
        match writer.write(bytes).await {
            Ok(n) => {
                total_written += n;
                // Slice the remaining bytes
                bytes = &bytes[n..];
            }
            Err(e) => {
                tracing::error!(
                    bytes_written = total_written,
                    error = %e,
                    error_kind = ?e.kind(),
                    "Failed to write to stream"
                );
                return Err(eyre::eyre!("Failed to write to stream: {}", e));
            }
        }
    }

    // Flush the writer to ensure all data is sent
    writer
        .flush()
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                error_kind = ?e.kind(),
                "Failed to flush stream"
            );
            e
        })
        .wrap_err("Failed to flush stream")?;

    tracing::debug!(
        bytes_sent = total_written,
        response = %response_str,
        "Response sent successfully"
    );

    Ok(())
}
