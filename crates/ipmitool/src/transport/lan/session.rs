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

//! IPMI v1.5 LAN session state machine.
//!
//! Tracks the session through the Get Session Challenge / Activate Session
//! handshake and into the active (authenticated) state. This is simpler than
//! the RMCP+ (lanplus) state machine because IPMI v1.5 has only a two-step
//! handshake.

use super::auth::AuthType;

// ==============================================================================
// Session State Machine
// ==============================================================================

/// Session states for the IPMI v1.5 LAN handshake.
///
/// The handshake progresses linearly:
///
/// ```text
/// Inactive → ChallengeReceived → Active → Closed
/// ```
///
/// Any error during the handshake returns the session to `Inactive`.
pub enum LanSessionState {
    /// No session established.
    Inactive,

    /// Get Session Challenge response received; ready to send Activate Session.
    ChallengeReceived {
        /// Temporary session ID from the BMC's challenge response.
        temp_session_id: u32,
        /// 16-byte challenge string from the BMC.
        challenge: [u8; 16],
    },

    /// Session fully established and ready for IPMI commands.
    Active(LanActiveSession),

    /// Session has been closed.
    Closed,
}

impl LanSessionState {
    /// Returns a human-readable name for the current state, for diagnostics.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Inactive => "Inactive",
            Self::ChallengeReceived { .. } => "ChallengeReceived",
            Self::Active(_) => "Active",
            Self::Closed => "Closed",
        }
    }
}

// ==============================================================================
// Active Session
// ==============================================================================

/// A fully-established IPMI v1.5 LAN session.
pub struct LanActiveSession {
    /// The BMC-assigned session ID (used in outgoing packet headers).
    pub session_id: u32,
    /// Authentication type negotiated during session activation.
    pub auth_type: AuthType,
    /// Monotonically increasing outbound session sequence number.
    session_seq: u32,
}

impl LanActiveSession {
    /// Create a new active session.
    ///
    /// `initial_seq` is the "Initial Message Sequence Number" from the
    /// Activate Session response (IPMI v1.5 Table 22-19). The C `ipmitool`
    /// uses this value directly as the first outbound sequence number. The
    /// first call to [`next_seq`](Self::next_seq) will return
    /// `initial_seq` (or `initial_seq + 1` if `initial_seq` is zero, since
    /// zero is reserved for pre-session messages).
    pub fn new(session_id: u32, auth_type: AuthType, initial_seq: u32) -> Self {
        // next_seq() adds 1 then returns, so subtract 1 to make the first
        // call return initial_seq. If initial_seq is 0, we start at u32::MAX
        // so next_seq returns 1 (skipping 0).
        let start = if initial_seq == 0 {
            0 // next_seq will return 1
        } else {
            initial_seq.wrapping_sub(1)
        };
        Self {
            session_id,
            auth_type,
            session_seq: start,
        }
    }

    /// Advance and return the next session sequence number.
    ///
    /// Sequence 0 is reserved for pre-session traffic, so the first call
    /// returns 1 and subsequent calls increment normally.
    pub fn next_seq(&mut self) -> u32 {
        self.session_seq = self.session_seq.wrapping_add(1);

        // Sequence 0 is reserved — skip it on wrap-around.
        if self.session_seq == 0 {
            self.session_seq = 1;
        }

        self.session_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Sequence Number Tests
    // =========================================================================

    #[test]
    fn next_seq_starts_at_one_when_initial_zero() {
        let mut session = LanActiveSession::new(1, AuthType::None, 0);
        assert_eq!(session.next_seq(), 1);
    }

    #[test]
    fn next_seq_starts_at_initial_seq() {
        // The BMC assigns an initial seq via the Activate Session response.
        let mut session = LanActiveSession::new(1, AuthType::None, 0x0111D8C1);
        assert_eq!(session.next_seq(), 0x0111D8C1);
        assert_eq!(session.next_seq(), 0x0111D8C2);
        assert_eq!(session.next_seq(), 0x0111D8C3);
    }

    #[test]
    fn next_seq_increments() {
        let mut session = LanActiveSession::new(1, AuthType::None, 0);
        assert_eq!(session.next_seq(), 1);
        assert_eq!(session.next_seq(), 2);
        assert_eq!(session.next_seq(), 3);
    }

    #[test]
    fn next_seq_skips_zero_on_wraparound() {
        let mut session = LanActiveSession::new(1, AuthType::None, 0);

        // Manually set sequence to just before wrap.
        session.session_seq = u32::MAX;

        // Next should wrap past 0 to 1.
        assert_eq!(session.next_seq(), 1);
        assert_eq!(session.next_seq(), 2);
    }

    // =========================================================================
    // State Name Tests
    // =========================================================================

    #[test]
    fn state_names() {
        assert_eq!(LanSessionState::Inactive.name(), "Inactive");
        assert_eq!(
            LanSessionState::ChallengeReceived {
                temp_session_id: 42,
                challenge: [0xAB; 16],
            }
            .name(),
            "ChallengeReceived"
        );
        assert_eq!(
            LanSessionState::Active(LanActiveSession::new(1, AuthType::None, 0)).name(),
            "Active"
        );
        assert_eq!(LanSessionState::Closed.name(), "Closed");
    }
}
