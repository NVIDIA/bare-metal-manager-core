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
use std::io;
use std::net::{AddrParseError, Ipv4Addr};
use std::str::Utf8Error;

use dhcproto::v4::relay::RelayCode;
use dhcproto::v4::{MessageType, OptionCode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DhcpError {
    #[error("IO Error: {0}")]
    IoError(#[from] io::Error),

    #[error("serde_yaml: {0}")]
    SerdeYaml(#[from] serde_yaml::Error),

    #[error("Missing Argument: {0}")]
    MissingArgument(String),

    #[error("Missing Option: {0:?}")]
    MissingOption(OptionCode),

    #[error("Missing Message Type: {0:?}")]
    UnhandledMessageType(MessageType),

    #[error("DhcpDecline message received for IP: {0}, mac: {1:?}")]
    DhcpDeclineMessage(String, String),

    #[error("Missing Relay Code: {0:?}")]
    MissingRelayCode(RelayCode),

    #[error("Invalid Input: {0}")]
    InvalidInput(String),

    #[error("Generic Error: {0}")]
    GenericError(String),

    #[error("GRPC Failure: {0}")]
    TonicStatusError(#[from] tonic::Status),

    #[error("Utf8 Decoding Failure: {0}")]
    Utf8Error(#[from] Utf8Error),

    #[error("Utf8 Decoding Failure: {0}")]
    PacketDecodeFailure(#[from] dhcproto::error::DecodeError),

    #[error("Utf8 Decoding Failure: {0}")]
    PacketEncodeFailure(#[from] dhcproto::error::EncodeError),

    #[error("Utf8 Decoding Failure: {0}")]
    AddressParseError(#[from] AddrParseError),

    #[error("Non relayed packet received: {0}. Dropping!")]
    NonRelayedPacket(Ipv4Addr),

    #[error("Unknown Packet: {0}")]
    UnknownPacket(u8),

    #[error("Packet received for other server: {0}")]
    NotMyPacket(String),

    #[error("Vendor class parse error: {0:?}")]
    VendorClassParseError(String),

    #[error("Multiple interfaces are provided, but only 1 is supported: {0}")]
    MultipleInterfacesProvidedOneSupported(usize),
}
