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
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use dhcp::mock_api_server;
use dhcproto::{Decodable, Decoder, v4};

mod common;

use common::{DHCPFactory, Kea, RELAY_IP};

// Must be u8 to be used a idx (last part of MAC and link IP)
// Must not exceed Kea config 'packet-queue-size', below, or packets  will be dropped.
const NUM_THREADS: u8 = 10;
const NUM_MSGS_PER_THREAD: usize = 100;
const NUM_EXPECTED: u64 = NUM_THREADS as u64 * NUM_MSGS_PER_THREAD as u64;

const READ_TIMEOUT: Duration = Duration::from_millis(500);

// Start a real Kea process, configured to be multi threaded, and send it some DISCOVERY messages from multiple threads.
// We pretend to be the relay because our hooks only accepted relayed packets.
//
// Kea should receive the packets, call our hooks, which should call MockAPIServer and then respond to
// the relay (aka gateway), which is us.
#[test]
fn test_real_kea_multithreaded() -> Result<(), eyre::Report> {
    // Start multi-threaded mock API server. The hooks call this over the network.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let api_server = rt.block_on(mock_api_server::MockAPIServer::start());

    let dhcp_in_port = 7000;
    let dhcp_out_port = 7001;

    // Start Kea process. Stops on drop.
    let mut kea = Kea::new(api_server.local_http_addr(), dhcp_in_port, dhcp_out_port)?;
    kea.run()?;

    // UDP socket to Kea. We're pretending to be dhcp-relay.
    let socket = UdpSocket::bind(format!("{RELAY_IP}:{dhcp_out_port}"))?;
    socket.connect(format!("127.0.0.1:{dhcp_in_port}"))?;
    socket.set_read_timeout(Some(READ_TIMEOUT))?;

    // The first packet doesn't get a response. I don't know why. dhcp-relay also sends two.
    // So sacrifice a packet, and wait to be sure it's the first packet received by Kea.
    let mut msg = DHCPFactory::discover(0);
    msg.set_xid(0);
    let pkt = DHCPFactory::encode(msg)?;
    socket.send(&pkt)?;
    thread::sleep(Duration::from_millis(20));

    let socket = Arc::new(socket);
    let recv_packets = Arc::new(AtomicU64::new(0));
    thread::scope(|s| {
        // idx -> mpsc::channel.
        // Sender blocks on this once it sends DISCOVERY. Receiver unblocks it on matching OFFER.
        let mut chan_map = HashMap::with_capacity(NUM_THREADS as usize);

        // In case of packet loss we need to abort all threads.
        // thread::scope join's them all on exit.
        let should_stop = Arc::new(AtomicBool::new(false));

        // Multiple send threads

        // Start from 1 because idx 0 was the sacrifice
        for idx in 1..=NUM_THREADS {
            let inner_socket = socket.clone();
            let s_should_stop = should_stop.clone();
            let (unblock, block) = channel();
            s.spawn(move || {
                // wait for receiver to start and avoid thundering herd
                thread::sleep(Duration::from_millis(50 + idx as u64));
                let msg_orig = DHCPFactory::discover(idx);
                let mut sent = 0;
                while sent < NUM_MSGS_PER_THREAD && !s_should_stop.load(Ordering::Relaxed) {
                    let mut msg = msg_orig.clone();
                    msg.set_xid(((sent as u32) << 8) | idx as u32);
                    let pkt = DHCPFactory::encode(msg).unwrap();
                    inner_socket.send(&pkt).unwrap();
                    sent += 1;
                    // wait for OFFER response to arrive
                    _ = block.recv();
                }
            });
            chan_map.insert(idx, unblock);
        }

        // Single receive thread

        let socket_recv = socket.clone();
        let r_packets = recv_packets.clone();
        let _receiver = s.spawn(move || {
            let mut recv_buf = [0u8; 1500]; // packet is 470 bytes, but allow for full MTU
            let mut received = 0;
            while received < NUM_EXPECTED {
                let n = match socket_recv.recv(&mut recv_buf) {
                    Ok(n) => n,
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        // Socket read timeout, indicates packets loss.
                        break;
                    }
                    Err(err) => {
                        panic!("socket recv unhandled error: {err}");
                    }
                };
                let msg = v4::Message::decode(&mut Decoder::new(&recv_buf[..n])).unwrap();
                assert_eq!(msg.opts().msg_type().unwrap(), v4::MessageType::Offer);
                let idx = msg.xid() as u8;
                received += 1;
                match chan_map.get(&idx) {
                    Some(handle) => _ = handle.send(()),
                    None => {
                        println!("idx:{idx} missing in thread handle map for {msg}");
                    }
                }
            }
            r_packets.store(received, Ordering::Relaxed);
            // unblock senders
            should_stop.store(true, Ordering::Relaxed);
            chan_map.values().for_each(|c| {
                _ = c.send(());
            });
        });

        // wait for all the OFFER responses to be received. scope does this for us.
    });
    assert_eq!(
        recv_packets.load(Ordering::Relaxed),
        NUM_EXPECTED,
        "Receive thread returned early because one or more packets were lost."
    );

    // Each thread only triggered one backend call because the other messages used the cache.
    let api_calls = api_server.calls_for(mock_api_server::ENDPOINT_DISCOVER_DHCP) as u8;
    assert_eq!(api_calls, NUM_THREADS + 1); // +1 for the sacrificial message

    Ok(())
}
