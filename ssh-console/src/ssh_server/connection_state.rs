/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::convert::TryFrom;
use std::sync::atomic::{AtomicU8, Ordering};

/// Represents the state of a connection to a BMC backend
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    ConnectionError = 3,
}

impl From<ConnectionState> for u8 {
    fn from(state: ConnectionState) -> u8 {
        state as u8
    }
}

impl TryFrom<u8> for ConnectionState {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ConnectionState::Disconnected),
            1 => Ok(ConnectionState::Connecting),
            2 => Ok(ConnectionState::Connected),
            3 => Ok(ConnectionState::ConnectionError),
            _ => Err(()),
        }
    }
}

/// Wrapper for an AtomicU8 representing a [`ConnectionState`], so that the state can be shared
/// between threads.
#[derive(Debug)]
pub struct AtomicConnectionState(AtomicU8);

impl AtomicConnectionState {
    #[inline]
    pub fn new(state: ConnectionState) -> Self {
        Self(AtomicU8::new(state.into()))
    }

    #[inline]
    pub fn load(&self) -> ConnectionState {
        ConnectionState::try_from(self.0.load(Ordering::SeqCst))
            .expect("BUG: connection state corrupted")
    }

    #[inline]
    pub fn store(&self, state: ConnectionState) {
        self.0.store(state.into(), Ordering::SeqCst);
    }
}

impl Default for AtomicConnectionState {
    fn default() -> Self {
        AtomicConnectionState::new(ConnectionState::Disconnected)
    }
}
