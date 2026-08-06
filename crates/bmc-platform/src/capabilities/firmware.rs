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

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{DriverOutcome, OpCx, PlatformError};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FirmwareInventory {
    pub id: String,
    pub description: Option<String>,
    pub version: Option<String>,
    pub release_date: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareUploadComponent {
    Bmc,
    Uefi,
    ErotBmc,
    ErotBios,
    CpldMid,
    CpldMb,
    CpldPdb,
    Psu { number: u32 },
    PcieSwitch { number: u32 },
    PcieRetimer { number: u32 },
    HgxBmc,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferProtocol {
    Ftp,
    Sftp,
    Http,
    Https,
    Scp,
    Tftp,
    Oem,
    Nfs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FirmwareUpdate {
    Multipart {
        path: PathBuf,
        reboot: bool,
        timeout: Duration,
        component: FirmwareUploadComponent,
    },
    Simple {
        image_uri: String,
        targets: Vec<String>,
        transfer_protocol: TransferProtocol,
    },
    HttpPush {
        path: PathBuf,
    },
}

/// Firmware inventory and simple-image update operations.
#[async_trait]
pub trait Firmware: Send + Sync {
    async fn inventory(&self, cx: &OpCx<'_>) -> Result<Vec<FirmwareInventory>, PlatformError>;

    async fn update(
        &self,
        cx: &OpCx<'_>,
        request: &FirmwareUpdate,
    ) -> Result<DriverOutcome, PlatformError>;
}
