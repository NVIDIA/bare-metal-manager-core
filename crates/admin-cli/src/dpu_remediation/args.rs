/*
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::dpu_remediations::RemediationId;
use carbide_uuid::machine::MachineId;
use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Create a remediation")]
    Create(CreateDpuRemediation),
    #[clap(about = "Approve a remediation")]
    Approve(ApproveDpuRemediation),
    #[clap(about = "Revoke a remediation")]
    Revoke(RevokeDpuRemediation),
    #[clap(about = "Enable a remediation")]
    Enable(EnableDpuRemediation),
    #[clap(about = "Disable a remediation")]
    Disable(DisableDpuRemediation),
    #[clap(about = "Display remediation information")]
    Show(ShowRemediation),
    #[clap(about = "Display information about applied remediations")]
    ListApplied(ListAppliedRemediations),
}

#[derive(Parser, Debug)]
pub struct CreateDpuRemediation {
    #[clap(help = "The filename of the script to run", long)]
    pub script_filename: String,
    #[clap(
        help = "specify the amount of retries for the remediation, defaults to no retries",
        long
    )]
    pub retries: Option<u32>,
    #[clap(
        long = "meta-name",
        value_name = "META_NAME",
        help = "The name that should be used as part of the Metadata for newly created Remediations.  Completely optional."
    )]
    pub meta_name: Option<String>,

    #[clap(
        long = "meta-description",
        value_name = "META_DESCRIPTION",
        help = "The description that should be used as part of the Metadata for newly created Remediations.  Completely optional."
    )]
    pub meta_description: Option<String>,

    #[clap(
        long = "label",
        value_name = "LABEL",
        help = "A label that will be added as metadata for the newly created Remediation. The labels key and value must be separated by a : character. E.g. DATACENTER:XYZ.  Completely optional.",
        action = clap::ArgAction::Append
    )]
    pub labels: Option<Vec<String>>,
}

impl CreateDpuRemediation {
    pub fn into_metadata(self) -> Option<::rpc::forge::Metadata> {
        if self.labels.is_none() && self.meta_name.is_none() && self.meta_description.is_none() {
            return None;
        }

        let mut labels = Vec::new();
        if let Some(list) = &self.labels {
            for label in list {
                let label = match label.split_once(':') {
                    Some((k, v)) => rpc::forge::Label {
                        key: k.trim().to_string(),
                        value: Some(v.trim().to_string()),
                    },
                    None => rpc::forge::Label {
                        key: label.trim().to_string(),
                        value: None,
                    },
                };
                labels.push(label);
            }
        }

        Some(::rpc::forge::Metadata {
            name: self.meta_name.unwrap_or_default(),
            description: self.meta_description.unwrap_or_default(),
            labels,
        })
    }
}

#[derive(Parser, Debug)]
pub struct ApproveDpuRemediation {
    #[clap(help = "The id of the remediation to approve", long)]
    pub id: RemediationId,
}

#[derive(Parser, Debug)]
pub struct RevokeDpuRemediation {
    #[clap(help = "The id of the remediation to revoke", long)]
    pub id: RemediationId,
}

#[derive(Parser, Debug)]
pub struct EnableDpuRemediation {
    #[clap(help = "The id of the remediation to enable", long)]
    pub id: RemediationId,
}

#[derive(Parser, Debug)]
pub struct DisableDpuRemediation {
    #[clap(help = "The id of the remediation to disable", long)]
    pub id: RemediationId,
}

#[derive(Parser, Debug)]
pub struct ShowRemediation {
    #[clap(help = "The remediation id to query, if not provided defaults to all")]
    pub id: Option<RemediationId>,
    #[clap(long, action)]
    pub display_script: bool,
}

#[derive(Parser, Debug)]
pub struct ListAppliedRemediations {
    #[clap(
        help = "The remediation id to query, in case the user wants to see which machines have a specific remediation applied.  Provide both arguments to see all the details for a specific remediation and machine.",
        long
    )]
    pub remediation_id: Option<RemediationId>,
    #[clap(
        help = "The machine id to query, in case the user wants to see which remediations have been applied to a specific box.  Provide both arguments to see all the details for a specific remediation and machine.",
        long
    )]
    pub machine_id: Option<MachineId>,
}
