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
use carbide_uuid::domain::DomainId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    pub id: DomainId,
    pub zone: String,
    pub kind: String,
    pub serial: u32,
    pub last_check: Option<u32>,
    pub notified_serial: Option<u32>,
    pub masters: Vec<String>,
}

impl From<DomainInfo> for rpc::protos::dns::DomainInfo {
    fn from(domain: DomainInfo) -> Self {
        rpc::protos::dns::DomainInfo {
            id: Some(domain.id),
            zone: domain.zone,
            kind: domain.kind,
            serial: domain.serial as i32,
            last_checked: domain.last_check.map(|v| v as i32),
            notified_serial: domain.notified_serial.map(|v| v as i32),
        }
    }
}

impl From<super::Domain> for DomainInfo {
    fn from(domain: super::Domain) -> Self {
        let soa = domain
            .soa
            .unwrap_or_else(|| super::SoaSnapshot::new(&domain.name));

        DomainInfo {
            id: domain.id,
            zone: domain.name + ".",
            kind: "native".to_string(),
            serial: soa.0.serial,
            last_check: None,
            notified_serial: None,
            masters: vec![],
        }
    }
}
