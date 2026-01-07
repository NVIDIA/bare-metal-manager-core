/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::machine::MachineId;
use clap::{ArgGroup, Parser};

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Show SKU information", visible_alias = "s")]
    Show(ShowSku),
    #[clap(about = "Show what machines are assigned a SKU")]
    ShowMachines(ShowSku),
    #[clap(
        about = "Generate SKU information from an existing machine",
        visible_alias = "g"
    )]
    Generate(GenerateSku),
    #[clap(about = "Create SKUs from a file", visible_alias = "c")]
    Create(CreateSku),
    #[clap(about = "Delete a SKU", visible_alias = "d")]
    Delete { sku_id: String },
    #[clap(about = "Assign a SKU to a machine", visible_alias = "a")]
    Assign {
        sku_id: String,
        machine_id: MachineId,
        #[clap(long)]
        force: bool,
    },
    #[clap(about = "Unassign a SKU from a machine", visible_alias = "u")]
    Unassign(UnassignSku),
    #[clap(about = "Verify a machine against its SKU", visible_alias = "v")]
    Verify { machine_id: MachineId },
    #[clap(about = "Update the metadata of a SKU")]
    UpdateMetadata(UpdateSkuMetadata),
    #[clap(about = "Update multiple SKU's metadata from a file")]
    BulkUpdateMetadata(BulkUpdateSkuMetadata),
    #[clap(about = "Replace the component list of a SKU")]
    Replace(CreateSku),
}

#[derive(Parser, Debug)]
pub struct ShowSku {
    #[clap(help = "Show SKU details")]
    pub sku_id: Option<String>,
}

#[derive(Parser, Debug)]
pub struct GenerateSku {
    #[clap(help = "The machine id of the machine to use to generate a SKU")]
    pub machine_id: MachineId,
    #[clap(help = "override the ID of the SKU", long)]
    pub id: Option<String>,
}

#[derive(Parser, Debug)]
pub struct CreateSku {
    #[clap(help = "The filename of the SKU data")]
    pub filename: String,
    #[clap(help = "override the ID of the SKU in the file data", long)]
    pub id: Option<String>,
}

#[derive(Parser, Debug)]
pub struct UnassignSku {
    #[clap(help = "The machine id of the machine to unassign")]
    pub machine_id: MachineId,
    #[clap(long)]
    pub force: bool,
}

#[derive(Parser, Debug)]
#[clap(group(ArgGroup::new("group").required(true).multiple(true).args(&["description", "device_type"])))]
pub struct UpdateSkuMetadata {
    #[clap(help = "SKU ID of the SKU to update")]
    pub sku_id: String,
    #[clap(help = "Update the SKU's description", long, group("group"))]
    pub description: Option<String>,
    #[clap(help = "Update the SKU's device type", long, group("group"))]
    pub device_type: Option<String>,
}

impl From<UpdateSkuMetadata> for ::rpc::forge::SkuUpdateMetadataRequest {
    fn from(value: UpdateSkuMetadata) -> Self {
        ::rpc::forge::SkuUpdateMetadataRequest {
            sku_id: value.sku_id,
            description: value.description,
            device_type: value.device_type,
        }
    }
}

#[derive(Parser, Debug)]
pub struct BulkUpdateSkuMetadata {
    #[clap(help = "The CSV file to use to update metadata for multiple skus")]
    pub filename: String,
}
