/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
