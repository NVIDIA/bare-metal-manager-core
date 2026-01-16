/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! DNS record type constants
//!
//! This module defines constants for DNS record types and their numeric codes
//! as specified in RFC 1035 and related RFCs.

// DNS record type string constants
pub const DNS_TYPE_SOA: &str = "SOA";
pub const DNS_TYPE_NS: &str = "NS";
pub const DNS_TYPE_A: &str = "A";
pub const DNS_TYPE_AAAA: &str = "AAAA";
pub const DNS_TYPE_CNAME: &str = "CNAME";
pub const DNS_TYPE_MX: &str = "MX";
pub const DNS_TYPE_TXT: &str = "TXT";
pub const DNS_TYPE_PTR: &str = "PTR";
pub const DNS_TYPE_SRV: &str = "SRV";
pub const DNS_TYPE_ANY: &str = "ANY";

// DNS QTYPE numeric codes from RFC 1035
pub const DNS_QTYPE_A: u16 = 1;
pub const DNS_QTYPE_NS: u16 = 2;
pub const DNS_QTYPE_CNAME: u16 = 5;
pub const DNS_QTYPE_SOA: u16 = 6;
pub const DNS_QTYPE_PTR: u16 = 12;
pub const DNS_QTYPE_MX: u16 = 15;
pub const DNS_QTYPE_TXT: u16 = 16;
pub const DNS_QTYPE_AAAA: u16 = 28;
pub const DNS_QTYPE_SRV: u16 = 33;
pub const DNS_QTYPE_ANY: u16 = 255;
