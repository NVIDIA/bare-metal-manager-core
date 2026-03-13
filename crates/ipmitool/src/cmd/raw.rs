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

//! Raw IPMI command passthrough.
//!
//! Sends arbitrary (netfn, cmd, data) triples and returns the raw response
//! data bytes, allowing callers to issue commands not covered by typed
//! command modules.

use crate::error::{IpmitoolError, Result};
use crate::transport::IpmiTransport;
use crate::types::{IpmiRequest, NetFn};

/// Send an arbitrary raw IPMI command.
///
/// The `netfn` and `cmd` are the raw byte values for the network function
/// and command code. The response data bytes (after the completion code)
/// are returned on success.
///
/// # Errors
///
/// Returns [`IpmitoolError::InvalidResponse`] if the supplied `netfn` does
/// not map to a known [`NetFn`] variant. Returns transport or completion
/// code errors as usual.
pub async fn raw_command(
    transport: &mut impl IpmiTransport,
    netfn: u8,
    cmd: u8,
    data: &[u8],
) -> Result<Vec<u8>> {
    let nf = NetFn::try_from(netfn).map_err(|unknown| {
        IpmitoolError::InvalidResponse(format!("unknown NetFn: 0x{unknown:02X}"))
    })?;

    let req = IpmiRequest::with_data(nf, cmd, data.to_vec());
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;
    Ok(resp.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    #[tokio::test]
    async fn raw_command_passthrough() {
        let mut transport = MockTransport::new();

        // Register a response for NetFn::App (0x06), cmd 0x01.
        let response_data = vec![0x00, 0xAA, 0xBB, 0xCC];
        transport.add_response(0x06, 0x01, response_data);

        let result = raw_command(&mut transport, 0x06, 0x01, &[])
            .await
            .expect("raw command should succeed");

        assert_eq!(result, vec![0xAA, 0xBB, 0xCC]);
    }

    #[tokio::test]
    async fn raw_command_with_data() {
        let mut transport = MockTransport::new();
        transport.add_response(0x00, 0x02, vec![0x00]);

        let result = raw_command(&mut transport, 0x00, 0x02, &[0x01])
            .await
            .expect("raw command with data should succeed");

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn raw_command_unknown_netfn_errors() {
        let mut transport = MockTransport::new();

        let result = raw_command(&mut transport, 0xFE, 0x01, &[]).await;
        assert!(result.is_err());
    }
}
