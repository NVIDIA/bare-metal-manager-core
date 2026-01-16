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

use serde::{Deserialize, Serialize};

// Represents metadata associated with a DNS domain.
///
/// This struct holds additional configuration information for a DNS domain,
/// such as which IP addresses or networks are allowed to perform AXFR (zone transfer) requests.
///
/// # Fields
///
/// * `allow_axfr_from` - A list of IP addresses or CIDR ranges as strings that are permitted to perform AXFR (zone transfer) requests.
///   This can be used to restrict zone transfers to trusted servers.
///
/// A list of IP addresses or CIDR ranges allowed to perform AXFR (zone transfer) requests.
///
/// This provides control over which external servers are permitted to retrieve
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub struct DomainMetadata {
    pub allow_axfr_from: Vec<String>,
}

impl DomainMetadata {
    pub fn update_allow_axfr_from(&mut self, axfr_list: Vec<String>) {
        self.allow_axfr_from = axfr_list
    }

    pub fn allow_axfr_from(&self) -> &Vec<String> {
        &self.allow_axfr_from
    }
}

impl From<rpc::protos::dns::Metadata> for DomainMetadata {
    fn from(metadata: rpc::protos::dns::Metadata) -> Self {
        DomainMetadata {
            allow_axfr_from: metadata.allow_axfr_from,
        }
    }
}

impl From<DomainMetadata> for rpc::protos::dns::Metadata {
    fn from(metadata: DomainMetadata) -> Self {
        rpc::protos::dns::Metadata {
            allow_axfr_from: vec![metadata.allow_axfr_from.join(",")],
        }
    }
}
