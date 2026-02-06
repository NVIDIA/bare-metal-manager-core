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

/// A hyper / TCP server that pretends to be carbide-api, for unit testing.
/// It responds to DHCP_DISCOVERY messages with a DHCP_OFFER of 172.20.0.{x}/32, where x is the
/// last byte of the MAC address sent in the DISCOVERY packet.
///
/// Module only included if #cfg(test)
///
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use ::rpc::forge as rpc;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response, body, header};
use hyper_util::rt::{TokioExecutor, TokioIo};
use mac_address::MacAddress;
use prost::Message;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::machine::Machine;

pub const ENDPOINT_DISCOVER_DHCP: &str = "/forge.Forge/DiscoverDhcp";

// Contents of the response
const DHCP_RESPONSE_FQDN: &str = "december-nitrogen.forge.local";
const DHCP_RESPONSE_ADDR_PREFIX: &str = "172.20.0";

pub fn base_dhcp_response(mac_address: MacAddress) -> rpc::DhcpRecord {
    rpc::DhcpRecord {
        machine_id: None,
        machine_interface_id: Some("88750d14-00fa-4d21-9fbc-d562046bc194".parse().unwrap()),
        segment_id: Some("267d40d1-75ba-4fee-bf76-a2ec2ce293fd".parse().unwrap()),
        subdomain_id: Some("023138e1-ebf1-4ef7-8a2c-bbce928a1601".parse().unwrap()),
        fqdn: DHCP_RESPONSE_FQDN.to_string(),
        mac_address: mac_address.to_string(),
        address: address_to_offer(mac_address),
        mtu: 1490,
        prefix: "172.20.0.0/24".to_string(),
        gateway: Some("172.20.0.1".to_string()),
        booturl: None,
        last_invalidation_time: None,
    }
}

// Encode a DhcpRecord to match gRPC HTTP/2 DATA frame that API server (via hyper) produces.
pub fn dhcp_response(mac_address_str: &str) -> Vec<u8> {
    let mac_address = mac_address_str.parse::<MacAddress>().unwrap();

    let mut r = base_dhcp_response(mac_address);

    // Specialization of response based on mac address
    // Meant to be extended, if let ()... isn't what we want here
    #[allow(clippy::single_match)]
    match mac_address.bytes() {
        [_, _, _, _, _, 0xaa] => {
            r.booturl =
                "https://api-specified-ipxe-url.forge/public/blobs/internal/x86_64/ipxe.efi"
                    .to_string()
                    .into();
        }
        _ => {}
    }

    let mut out = Vec::with_capacity(224);
    out.push(0); // Message is not compressed
    out.extend_from_slice(&(r.encoded_len() as u32).to_be_bytes());
    r.encode(&mut out).unwrap();
    out
}

// Given a MAC address, make the IP address we should offer it
fn address_to_offer(mac: MacAddress) -> String {
    format!("{}.{}", DHCP_RESPONSE_ADDR_PREFIX, mac.bytes()[5])
}

// Does this Machine the result we expected?
pub fn matches_mock_response(machine: &Machine) -> bool {
    machine.inner.fqdn == DHCP_RESPONSE_FQDN
        && machine.inner.address == address_to_offer(machine.discovery_info.mac_address)
}

pub struct MockAPIServer {
    calls: Arc<Mutex<HashMap<String, usize>>>,
    handle: JoinHandle<Result<(), hyper::Error>>,
    tx: Option<tokio::sync::oneshot::Sender<()>>,
    local_addr: String,
    inject_failure: Arc<Mutex<bool>>,
}

#[derive(Debug)]
enum MockAPIServerError {
    MockAPIFetchMachineError,
}

impl std::error::Error for MockAPIServerError {}

impl std::fmt::Display for MockAPIServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "MockAPIServer injected test error")
    }
}

impl MockAPIServer {
    // Start a Hyper HTTP/2 server as a task on give runtime
    pub async fn start() -> MockAPIServer {
        // :0 asks the kernel to assign an unused port
        // Gitlab CI (or some part of our config of it) does not support IPv6
        let addr = SocketAddr::V4(SocketAddrV4::from_str("127.0.0.1:0").unwrap());

        let inject_failure = Arc::new(Mutex::new(false));
        let i2 = inject_failure.clone();
        let calls = Arc::new(Mutex::new(HashMap::new()));
        let c2 = calls.clone();
        let listener = TcpListener::bind(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap().to_string();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            loop {
                let c3 = c2.clone();
                let i3 = i2.clone();
                tokio::select! {
                    result = listener.accept() => {
                        let (stream, _) = result.unwrap();
                        tokio::spawn(async move {
                            http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(stream), service_fn(move |req: Request<body::Incoming>| {
                                let c3 = c3.clone();
                                let i3 = i3.clone();
                                async move {
                                    Ok::<Response<Full<Bytes>>, hyper::Error>(MockAPIServer::handler(req, c3.clone(), i3.clone()).await.unwrap())
                                }
                            })).await.inspect_err(|e| eprintln!("ERROR: {e:?}")).unwrap()
                        });
                    }
                    _ = &mut rx => {
                        break;
                    }
                }
            }
            Ok::<(), hyper::Error>(())
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await; // let it start
        MockAPIServer {
            calls,
            handle,
            local_addr: format!("http://{local_addr}"),
            tx: Some(tx),
            inject_failure,
        }
    }

    // The HTTP address of the server
    pub fn local_http_addr(&self) -> &str {
        &self.local_addr
    }

    pub fn set_inject_failure(&mut self, fail: bool) {
        *self.inject_failure.lock().unwrap() = fail;
    }

    // Number of times the given endpoint has been hit
    pub fn calls_for(&self, endpoint: &str) -> usize {
        let l = self.calls.lock().unwrap();
        if l.contains_key(endpoint) {
            *l.get(endpoint).unwrap()
        } else {
            0
        }
    }

    async fn handler(
        req: Request<Incoming>,
        calls: Arc<Mutex<HashMap<String, usize>>>,
        fail: Arc<Mutex<bool>>,
    ) -> Result<Response<Full<Bytes>>, MockAPIServerError> {
        let path = req.uri().path();
        calls
            .lock()
            .unwrap()
            .entry(path.to_owned())
            .and_modify(|e| *e += 1)
            .or_insert(1);
        match path {
            // Add the endpoints you need here
            ENDPOINT_DISCOVER_DHCP => {
                let inject_failure = *fail.lock().unwrap();
                if inject_failure {
                    Err(MockAPIServerError::MockAPIFetchMachineError)
                } else {
                    Ok(Response::new(
                        MockAPIServer::discover_dhcp(req).await.into(),
                    ))
                }
            }
            "/forge.Forge/Version" => respond(rpc::BuildInfo::default()),
            _ => panic!("DHCP -> API wrong uri: {}", req.uri().path()),
        }
    }

    async fn discover_dhcp(req: Request<Incoming>) -> Vec<u8> {
        let input_bytes = req.into_body().collect().await.unwrap().to_bytes();

        // slice is to strip the gRPC parts: 1 byte is_compressed and a 4 byte message length
        let disco = rpc::DhcpDiscovery::decode(input_bytes.slice(5..)).unwrap();
        dhcp_response(&disco.mac_address)
    }
}

impl Drop for MockAPIServer {
    // Stop the Hyper server
    fn drop(&mut self) {
        let _ = self.tx.take().expect("missing tx").send(());
        self.handle.abort();
    }
}

/// Takes an rpc object (built from rpc/proto/forge.proto) and turns into into a gRPC axum response
fn respond(out: impl prost::Message) -> Result<Response<Full<Bytes>>, MockAPIServerError> {
    let msg_len = out.encoded_len() as u32;
    let mut body = Vec::with_capacity(1 + 4 + msg_len as usize);
    // first byte is compression: 0 means none
    body.push(0u8);
    // next four bytes are length as bigendian u32
    body.extend_from_slice(&msg_len.to_be_bytes());
    // and finally the message
    out.encode(&mut body).unwrap();

    Ok(Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "application/grpc+tonic")
        .body(body.into())
        .unwrap())
}
