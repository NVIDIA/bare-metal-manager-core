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

//! CLI handler for sending raw IPMI commands.
//!
//! Parses hex-encoded netfn, cmd, and data bytes from the command line,
//! sends them as-is, and prints the response bytes in hex.

use eyre::Context;

use crate::transport::IpmiTransport;
use crate::types::{IpmiRequest, NetFn};

/// Arguments for a raw IPMI command.
#[derive(clap::Args)]
pub struct RawCommand {
    /// Network function code (hex, e.g. 0x06).
    pub netfn: String,
    /// Command code (hex, e.g. 0x01).
    pub cmd: String,
    /// Data bytes (hex, e.g. 0x01 0x02 0x03).
    pub data: Vec<String>,
}

/// Parse a hex string (with optional "0x" prefix) into a u8.
fn parse_hex_byte(s: &str) -> eyre::Result<u8> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u8::from_str_radix(s, 16).context(format!("parse hex byte from '{s}'"))
}

/// Send a raw IPMI command and print the response as hex bytes.
///
/// # Errors
///
/// Returns an error if hex parsing fails or the IPMI transport fails.
pub async fn run(
    transport: &mut impl IpmiTransport,
    cmd: RawCommand,
) -> eyre::Result<()> {
    let netfn_byte = parse_hex_byte(&cmd.netfn).context("parse netfn")?;
    let cmd_byte = parse_hex_byte(&cmd.cmd).context("parse command code")?;

    let data: Vec<u8> = cmd
        .data
        .iter()
        .enumerate()
        .map(|(i, s)| parse_hex_byte(s).context(format!("parse data byte {i}")))
        .collect::<eyre::Result<Vec<u8>>>()?;

    let netfn = NetFn::try_from(netfn_byte).map_err(|code| {
        eyre::eyre!("unknown network function: 0x{code:02X}")
    })?;

    let req = if data.is_empty() {
        IpmiRequest::new(netfn, cmd_byte)
    } else {
        IpmiRequest::with_data(netfn, cmd_byte, data)
    };

    let resp = transport
        .send_recv(&req)
        .await
        .context("send raw IPMI command")?;
    resp.check_completion().context("raw IPMI command")?;

    // Print response data bytes in hex, space-separated.
    let hex_str: Vec<String> = resp.data.iter().map(|b| format!("0x{b:02X}")).collect();
    if hex_str.is_empty() {
        println!("(no response data)");
    } else {
        println!("{}", hex_str.join(" "));
    }

    Ok(())
}
