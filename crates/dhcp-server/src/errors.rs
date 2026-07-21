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
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("serde_yaml: {0}")]
    SerdeYaml(#[from] serde_yaml::Error),

    #[error("missing argument: {0}")]
    MissingArgument(String),

    #[error("missing option: {0:?}")]
    MissingOption(OptionCode),

    #[error("missing message type: {0:?}")]
    UnhandledMessageType(MessageType),

    #[error("DhcpDecline message received for IP: {0}, mac: {1:?}")]
    DhcpDeclineMessage(String, String),

    #[error("missing relay code: {0:?}")]
    MissingRelayCode(RelayCode),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("generic error: {0}")]
    GenericError(String),

    #[error("GRPC failure: {0}")]
    TonicStatusError(#[from] tonic::Status),

    #[error("utf8 decoding failure: {0}")]
    Utf8Error(#[from] Utf8Error),

    #[error("utf8 decoding failure: {0}")]
    PacketDecodeFailure(#[from] dhcproto::error::DecodeError),

    #[error("utf8 decoding failure: {0}")]
    PacketEncodeFailure(#[from] dhcproto::error::EncodeError),

    #[error("utf8 decoding failure: {0}")]
    AddressParseError(#[from] AddrParseError),

    #[error("non relayed packet received: {0}. dropping!")]
    NonRelayedPacket(Ipv4Addr),

    #[error("unknown packet: {0}")]
    UnknownPacket(u8),

    #[error("packet received for other server: {0}")]
    NotMyPacket(String),

    #[error("vendor class parse error: {0:?}")]
    VendorClassParseError(String),

    #[error("multiple interfaces are provided, but only 1 is supported: {0}")]
    MultipleInterfacesProvidedOneSupported(usize),
}
