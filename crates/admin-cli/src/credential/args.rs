/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use clap::{Parser, ValueEnum};
use mac_address::MacAddress;

const DEFAULT_IB_FABRIC_NAME: &str = "default";

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
    #[clap(about = "Add UFM credential")]
    AddUFM(AddUFMCredential),
    #[clap(about = "Delete UFM credential")]
    DeleteUFM(DeleteUFMCredential),
    #[clap(about = "Generate UFM credential")]
    GenerateUFMCert(GenerateUFMCertCredential),
    #[clap(about = "Add BMC credentials")]
    AddBMC(AddBMCredential),
    #[clap(about = "Delete BMC credentials")]
    DeleteBMC(DeleteBMCredential),
    #[clap(
        about = "Add site-wide DPU UEFI default credential (NOTE: this parameter can be set only once)"
    )]
    AddUefi(AddUefiCredential),
    #[clap(about = "Add manufacturer factory default BMC user/pass for a given vendor")]
    AddHostFactoryDefault(AddHostFactoryDefaultCredential),
    #[clap(about = "Add manufacturer factory default BMC user/pass for the DPUs")]
    AddDpuFactoryDefault(AddDpuFactoryDefaultCredential),
    #[clap(about = "Add NmxM credentials")]
    AddNmxM(AddNmxMCredential),
    #[clap(about = "Delete NmxM credentials")]
    DeleteNmxM(DeleteNmxMCredential),
}

#[derive(Parser, Debug, Clone)]
pub struct AddUFMCredential {
    #[clap(long, required(true), help = "The UFM url")]
    pub url: String,

    #[clap(long, default_value(""), help = "The UFM token")]
    pub token: String,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteUFMCredential {
    #[clap(long, required(true), help = "The UFM url")]
    pub url: String,
}

#[derive(Parser, Debug, Clone)]
pub struct GenerateUFMCertCredential {
    #[clap(long, default_value_t = DEFAULT_IB_FABRIC_NAME.to_string(), help = "Infiniband fabric.")]
    pub fabric: String,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum BmcCredentialType {
    // Site Wide BMC Root Account Credentials
    SiteWideRoot,
    // BMC Specific Root Credentials
    BmcRoot,
    // BMC Specific Forge-Admin Credentials
    BmcForgeAdmin,
}

impl From<BmcCredentialType> for rpc::forge::CredentialType {
    fn from(c_type: BmcCredentialType) -> Self {
        use rpc::forge::CredentialType::*;
        match c_type {
            BmcCredentialType::SiteWideRoot => SiteWideBmcRoot,
            BmcCredentialType::BmcRoot => RootBmcByMacAddress,
            BmcCredentialType::BmcForgeAdmin => BmcForgeAdminByMacAddress,
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct AddBMCredential {
    #[clap(
        long,
        require_equals(true),
        required(true),
        help = "The BMC Credential kind"
    )]
    pub kind: BmcCredentialType,
    #[clap(long, required(true), help = "The password of BMC")]
    pub password: String,
    #[clap(long, help = "The username of BMC")]
    pub username: Option<String>,
    #[clap(long, help = "The MAC address of the BMC")]
    pub mac_address: Option<MacAddress>,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteBMCredential {
    #[clap(
        long,
        require_equals(true),
        required(true),
        help = "The BMC Credential kind"
    )]
    pub kind: BmcCredentialType,
    #[clap(long, help = "The MAC address of the BMC")]
    pub mac_address: Option<MacAddress>,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum UefiCredentialType {
    Dpu,
    Host,
}

impl From<UefiCredentialType> for rpc::forge::CredentialType {
    fn from(c_type: UefiCredentialType) -> Self {
        use rpc::forge::CredentialType::*;
        match c_type {
            UefiCredentialType::Dpu => DpuUefi,
            UefiCredentialType::Host => HostUefi,
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct AddUefiCredential {
    #[clap(long, require_equals(true), required(true), help = "The UEFI kind")]
    pub kind: UefiCredentialType,

    #[clap(long, require_equals(true), help = "The UEFI password")]
    pub password: String,
}

#[derive(Parser, Debug, Clone)]
pub struct AddHostFactoryDefaultCredential {
    #[clap(long, required(true), help = "Default username: root, ADMIN, etc")]
    pub username: String,
    #[clap(long, required(true), help = "Manufacturer default password")]
    pub password: String,
    #[clap(long, required(true))]
    pub vendor: bmc_vendor::BMCVendor,
}

#[derive(Parser, Debug, Clone)]
pub struct AddDpuFactoryDefaultCredential {
    #[clap(long, required(true), help = "Default username: root, ADMIN, etc")]
    pub username: String,
    #[clap(long, required(true), help = "DPU manufacturer default password")]
    pub password: String,
}

#[derive(Parser, Debug, Clone)]
pub struct AddNmxMCredential {
    #[clap(long, required(true), help = "Username")]
    pub username: String,
    #[clap(long, required(true), help = "password")]
    pub password: String,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteNmxMCredential {
    #[clap(long, required(true), help = "NmxM url")]
    pub username: String,
}
