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

//! IPMI v1.5 LAN transport implementation.
//!
//! This module implements the IPMI v1.5 session lifecycle over RMCP (UDP
//! port 623), for BMCs that do not support RMCP+ (IPMI v2.0). The session
//! establishment follows the four-step handshake:
//!
//! 1. Get Channel Authentication Capabilities
//! 2. Get Session Challenge
//! 3. Activate Session
//! 4. Set Session Privilege Level
//!
//! Unlike RMCP+, v1.5 has no encryption and no HMAC integrity — only an
//! MD5 auth code in the session header for per-message authentication.

pub mod auth;
pub mod packet;
pub mod session;

use std::time::Duration;

use byteorder::{ByteOrder, LittleEndian};
use tokio::net::UdpSocket;
use tracing::{debug, instrument, trace, warn};

use self::auth::{compute_md5_auth_code, AuthType};
use self::packet::{build_v15_packet, parse_v15_packet};
use self::session::{LanActiveSession, LanSessionState};
use crate::error::{IpmitoolError, Result};
use crate::transport::lanplus::header::IpmiMsgHeader;
use crate::transport::IpmiTransport;
use crate::types::{IpmiRequest, IpmiResponse, NetFn, PrivilegeLevel};
use crate::ConnectionConfig;

/// Maximum size of a single RMCP UDP packet.
const MAX_PACKET_SIZE: usize = 1024;

/// Default initial timeout for UDP recv.
const INITIAL_TIMEOUT: Duration = Duration::from_secs(2);

// ==============================================================================
// LAN Transport
// ==============================================================================

/// IPMI v1.5 LAN transport.
///
/// Manages a UDP socket, the v1.5 session state machine, and the IPMI
/// message sequence number. Created via [`LanTransport::connect`], which
/// performs the four-step session establishment before returning.
pub struct LanTransport {
    socket: UdpSocket,
    session: LanSessionState,
    config: ConnectionConfig,
    /// 6-bit IPMI message sequence number (0-63), used in the inner IPMI
    /// message header to correlate requests with responses.
    rq_seq: u8,
}

impl LanTransport {
    /// Connect to a BMC and establish an IPMI v1.5 session.
    ///
    /// Opens a UDP socket, then runs the four-step session establishment:
    /// Get Channel Auth Caps -> Get Session Challenge -> Activate Session
    /// -> Set Session Privilege Level.
    ///
    /// # Errors
    ///
    /// Returns an error if the network is unreachable, the BMC rejects the
    /// session, or authentication fails.
    #[instrument(skip(config), fields(host = %config.host, port = config.port))]
    pub async fn connect(config: ConnectionConfig) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = format!("{}:{}", config.host, config.port);
        socket.connect(&addr).await?;

        debug!(%addr, "UDP socket connected (IPMI v1.5 LAN)");

        let mut transport = Self {
            socket,
            session: LanSessionState::Inactive,
            config,
            rq_seq: 0,
        };

        transport.establish_session().await?;

        Ok(transport)
    }

    /// Advance and return the next 6-bit IPMI request sequence number (0-63).
    fn next_rq_seq(&mut self) -> u8 {
        self.rq_seq = (self.rq_seq + 1) & 0x3F;
        self.rq_seq
    }

    // ==========================================================================
    // Session Establishment (4-step)
    // ==========================================================================

    /// Run the complete v1.5 session establishment sequence.
    async fn establish_session(&mut self) -> Result<()> {
        // Step 1: Get Channel Authentication Capabilities.
        //
        // This tells us which auth types the BMC supports on the current
        // channel. We send it unauthenticated (auth_type=None, session_id=0).
        let auth_type = self
            .get_channel_auth_capabilities()
            .await
            .map_err(|e| IpmitoolError::Transport(format!(
                "Get Channel Auth Capabilities failed: {e}"
            )))?;
        debug!(?auth_type, "negotiated auth type");

        // Step 2: Get Session Challenge.
        //
        // Sends our username to the BMC, which returns a temporary session ID
        // and a 16-byte challenge string. Still unauthenticated.
        let (temp_session_id, challenge) = self
            .get_session_challenge(auth_type)
            .await
            .map_err(|e| IpmitoolError::Transport(format!(
                "Get Session Challenge failed: {e}"
            )))?;
        debug!(temp_session_id, "session challenge received");

        self.session = LanSessionState::ChallengeReceived {
            temp_session_id,
            challenge,
        };

        // Step 3: Activate Session.
        //
        // The Activate Session request is still a pre-session message: the
        // session header uses seq=0. The request DATA carries the initial
        // outbound seq that subsequent messages will start from.
        let (session_id, initial_seq) = self
            .activate_session(auth_type, temp_session_id, &challenge)
            .await
            .map_err(|e| IpmitoolError::Transport(format!(
                "Activate Session failed: {e}"
            )))?;
        debug!(session_id, initial_seq, "session activated");

        self.session = LanSessionState::Active(LanActiveSession::new(
            session_id, auth_type, initial_seq,
        ));

        // Step 4: Set Session Privilege Level to Administrator.
        self.set_session_privilege(PrivilegeLevel::Administrator)
            .await
            .map_err(|e| IpmitoolError::Transport(format!(
                "Set Session Privilege Level failed: {e}"
            )))?;
        debug!("privilege level set to Administrator");

        Ok(())
    }

    /// Step 1: Get Channel Authentication Capabilities.
    ///
    /// Queries the BMC for supported auth types on the current channel (0x0E).
    /// Returns the best available auth type (MD5 preferred, then None).
    async fn get_channel_auth_capabilities(&mut self) -> Result<AuthType> {
        // NetFn=App (0x06), Cmd=0x38 (Get Channel Authentication Capabilities)
        // Data: [channel=0x0E (current), requested_privilege=0x04 (Admin)]
        let rq_seq = self.next_rq_seq();
        let ipmi_msg = IpmiMsgHeader::request(0x06, 0x38, rq_seq)
            .build_message(&[0x0E, PrivilegeLevel::Administrator as u8]);

        let packet = build_v15_packet(AuthType::None, 0, 0, None, &ipmi_msg);
        let resp_bytes = self.send_recv_raw(&packet).await?;
        let parsed = parse_v15_packet(&resp_bytes)?;
        let (_hdr, data) = IpmiMsgHeader::parse_message(parsed.payload)?;
        let resp = IpmiResponse::from_bytes(data)?;
        resp.check_completion()?;

        // Response data layout (IPMI v2.0 spec Table 22-15):
        //   [0] Channel number
        //   [1] Auth type support bitmask:
        //       bit 0 = None, bit 1 = MD2, bit 2 = MD5, bit 4 = Straight password
        //   [2..] Additional capability flags (we don't need them)
        if resp.data.len() < 2 {
            return Err(IpmitoolError::InvalidResponse(
                "Get Channel Auth Capabilities response too short".to_owned(),
            ));
        }

        let auth_support = resp.data[1];
        trace!(auth_support = format!("0x{auth_support:02X}"), "auth type support bitmask");

        // Pick the best available auth type: MD5 > None.
        if auth_support & (1 << 2) != 0 {
            Ok(AuthType::Md5)
        } else if auth_support & (1 << 0) != 0 {
            Ok(AuthType::None)
        } else {
            Err(IpmitoolError::AuthenticationFailed(
                "BMC does not support MD5 or None auth types".to_owned(),
            ))
        }
    }

    /// Step 2: Get Session Challenge.
    ///
    /// Sends our username (null-padded to 16 bytes) and receives a temporary
    /// session ID and 16-byte challenge string.
    async fn get_session_challenge(
        &mut self,
        auth_type: AuthType,
    ) -> Result<(u32, [u8; 16])> {
        // NetFn=App (0x06), Cmd=0x39 (Get Session Challenge)
        // Data: [auth_type, username (16 bytes, null-padded)]
        let mut req_data = Vec::with_capacity(17);
        req_data.push(auth_type as u8);

        let username = self.config.username.as_bytes();
        let mut username_padded = [0u8; 16];
        let copy_len = username.len().min(16);
        username_padded[..copy_len].copy_from_slice(&username[..copy_len]);
        req_data.extend_from_slice(&username_padded);

        let rq_seq = self.next_rq_seq();
        let ipmi_msg =
            IpmiMsgHeader::request(0x06, 0x39, rq_seq).build_message(&req_data);

        let packet = build_v15_packet(AuthType::None, 0, 0, None, &ipmi_msg);
        let resp_bytes = self.send_recv_raw(&packet).await?;
        let parsed = parse_v15_packet(&resp_bytes)?;
        let (_hdr, data) = IpmiMsgHeader::parse_message(parsed.payload)?;
        let resp = IpmiResponse::from_bytes(data)?;
        resp.check_completion()?;

        // Response: [0..4] temp session ID (LE), [4..20] challenge string
        if resp.data.len() < 20 {
            return Err(IpmitoolError::InvalidResponse(
                "Get Session Challenge response too short".to_owned(),
            ));
        }

        let temp_session_id = LittleEndian::read_u32(&resp.data[0..4]);
        let mut challenge = [0u8; 16];
        challenge.copy_from_slice(&resp.data[4..20]);

        Ok((temp_session_id, challenge))
    }

    /// Step 3: Activate Session.
    ///
    /// The Activate Session request is still a pre-session message: the session
    /// header carries `session_seq=0` and the temp session ID. The initial
    /// outbound sequence number in the request DATA tells the BMC what seq to
    /// expect for subsequent (post-activation) messages.
    ///
    /// The C ipmitool sends `initial_outbound_seq=0` in the data field and
    /// then starts post-activation messages at seq=1 (skipping the reserved 0).
    /// We match that behavior for maximum BMC compatibility.
    async fn activate_session(
        &mut self,
        auth_type: AuthType,
        temp_session_id: u32,
        challenge: &[u8; 16],
    ) -> Result<(u32, u32)> {
        // NetFn=App (0x06), Cmd=0x3A (Activate Session)
        // Data: [auth_type, privilege, challenge (16 bytes), initial_outbound_seq (LE 4 bytes)]
        let mut req_data = Vec::with_capacity(22);
        req_data.push(auth_type as u8);
        req_data.push(PrivilegeLevel::Administrator as u8);
        req_data.extend_from_slice(challenge);

        // Initial outbound seq = 0 in the data field, matching C ipmitool.
        // Post-activation, the first next_seq() call returns 1 (skipping 0).
        req_data.extend_from_slice(&[0u8; 4]);

        let rq_seq = self.next_rq_seq();
        let ipmi_msg =
            IpmiMsgHeader::request(0x06, 0x3A, rq_seq).build_message(&req_data);

        // The Activate Session request is pre-session: session_seq=0 in the
        // header. The auth code is computed with session_seq=0 as well, since
        // the auth code formula uses the header's session_seq field.
        let auth_code = match auth_type {
            AuthType::Md5 => {
                Some(compute_md5_auth_code(
                    self.config.password.as_bytes(),
                    temp_session_id,
                    &ipmi_msg,
                    0, // session_seq = 0 for pre-session messages
                ))
            }
            AuthType::None => None,
        };

        let packet = build_v15_packet(
            auth_type,
            0, // session_seq = 0 for pre-session messages
            temp_session_id,
            auth_code.as_ref(),
            &ipmi_msg,
        );
        let resp_bytes = self.send_recv_raw(&packet).await?;
        let parsed = parse_v15_packet(&resp_bytes)?;
        let (_hdr, data) = IpmiMsgHeader::parse_message(parsed.payload)?;
        let resp = IpmiResponse::from_bytes(data)?;
        resp.check_completion()?;

        // Response layout (IPMI v1.5 Table 22-19, after completion code):
        //   [0]    Auth type for remainder of session
        //   [1..5] Session ID (LE, 4 bytes)
        //   [5..9] Initial message sequence number (LE, 4 bytes)
        //   [9]    Maximum privilege level (optional)
        //
        // NOTE: there is no separate privilege-level byte before the session ID.
        // The session ID starts at data[1], not data[2].
        if resp.data.len() < 9 {
            return Err(IpmitoolError::InvalidResponse(
                "Activate Session response too short".to_owned(),
            ));
        }

        let session_id = LittleEndian::read_u32(&resp.data[1..5]);
        let initial_inbound_seq = LittleEndian::read_u32(&resp.data[5..9]);

        Ok((session_id, initial_inbound_seq))
    }

    /// Step 4: Set Session Privilege Level.
    async fn set_session_privilege(
        &mut self,
        privilege: PrivilegeLevel,
    ) -> Result<()> {
        // NetFn=App (0x06), Cmd=0x3B (Set Session Privilege Level)
        let req = IpmiRequest::with_data(
            NetFn::App,
            0x3B,
            vec![privilege as u8],
        );
        let resp = self.send_recv(&req).await?;
        resp.check_completion()?;
        Ok(())
    }

    // ==========================================================================
    // Raw UDP Send/Receive
    // ==========================================================================

    /// Send a raw packet and receive the response, with retries and escalating
    /// timeout.
    async fn send_recv_raw(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let max_retries = self.config.retries;
        let mut timeout = INITIAL_TIMEOUT;

        trace!(len = packet.len(), hex = hex::encode(packet), "sending v1.5 packet");

        for attempt in 0..=max_retries {
            self.socket.send(packet).await?;

            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            match tokio::time::timeout(timeout, self.socket.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    buf.truncate(n);
                    trace!(len = n, hex = hex::encode(&buf), "received v1.5 packet");
                    return Ok(buf);
                }
                Ok(Err(e)) => return Err(IpmitoolError::Io(e)),
                Err(_) => {
                    if attempt < max_retries {
                        warn!(
                            attempt = attempt + 1,
                            max_retries,
                            "timeout, retrying with increased timeout"
                        );
                        // Escalate timeout by 1 second per retry.
                        timeout += Duration::from_secs(1);
                    }
                }
            }
        }

        Err(IpmitoolError::Timeout {
            retries: max_retries,
        })
    }
}

impl IpmiTransport for LanTransport {
    /// Send an IPMI request and wait for the response.
    ///
    /// Builds the inner IPMI message, wraps it in a v1.5 packet with auth
    /// code (if MD5), sends over UDP, then receives and parses the response.
    async fn send_recv(&mut self, req: &IpmiRequest) -> Result<IpmiResponse> {
        // Extract session parameters up front to avoid borrow conflicts.
        let (session_id, auth_type, seq) = match &mut self.session {
            LanSessionState::Active(session) => {
                let sid = session.session_id;
                let at = session.auth_type;
                let seq = session.next_seq();
                (sid, at, seq)
            }
            other => {
                return Err(IpmitoolError::InvalidSessionState {
                    expected: "Active",
                    actual: other.name(),
                });
            }
        };

        let rq_seq = self.next_rq_seq();
        let netfn: u8 = req.netfn.into();

        // Build the inner IPMI message (header + data + checksums).
        let ipmi_msg =
            IpmiMsgHeader::request(netfn, req.cmd, rq_seq).build_message(&req.data);

        // Compute auth code for MD5, or None for unauthenticated.
        let auth_code = match auth_type {
            AuthType::Md5 => Some(compute_md5_auth_code(
                self.config.password.as_bytes(),
                session_id,
                &ipmi_msg,
                seq,
            )),
            AuthType::None => None,
        };

        let packet = build_v15_packet(
            auth_type,
            seq,
            session_id,
            auth_code.as_ref(),
            &ipmi_msg,
        );

        let resp_bytes = self.send_recv_raw(&packet).await?;
        let parsed = parse_v15_packet(&resp_bytes)?;

        // Parse the inner IPMI message from the response payload.
        let (_resp_header, response_data) =
            IpmiMsgHeader::parse_message(parsed.payload)?;

        IpmiResponse::from_bytes(response_data)
    }

    /// Close the IPMI v1.5 session by sending a Close Session command.
    async fn close(&mut self) -> Result<()> {
        if let LanSessionState::Active(session) = &self.session {
            let session_id = session.session_id;

            // Close Session: NetFn=App (0x06), Cmd=0x3C.
            // Data = 4-byte LE session ID.
            let mut close_data = [0u8; 4];
            LittleEndian::write_u32(&mut close_data, session_id);

            let close_req =
                IpmiRequest::with_data(NetFn::App, 0x3C, close_data.to_vec());

            match self.send_recv(&close_req).await {
                Ok(_) => debug!("session closed successfully"),
                Err(e) => warn!(error = %e, "error closing session (ignored)"),
            }
        }

        self.session = LanSessionState::Closed;
        Ok(())
    }
}
