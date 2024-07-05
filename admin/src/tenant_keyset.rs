/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::fmt::Write;

use super::cfg::carbide_options::ShowTenantKeySet;
use super::{rpc, CarbideCliResult};
use crate::cfg::carbide_options::OutputFormat;
use crate::CarbideCliError;
use ::rpc::forge as forgerpc;
use ::rpc::forge_tls_client::ApiConfig;
use prettytable::{row, Table};

pub async fn handle_show(
    args: ShowTenantKeySet,
    output_format: OutputFormat,
    api_config: &ApiConfig<'_>,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if args.id.is_empty() {
        show_keysets(is_json, api_config, page_size, args.tenant_org_id).await?;
        return Ok(());
    }
    show_keyset_details(args.id, is_json, api_config).await?;
    Ok(())
}

async fn show_keysets(
    json: bool,
    api_config: &ApiConfig<'_>,
    page_size: usize,
    tenant_org_id: Option<String>,
) -> CarbideCliResult<()> {
    let all_ids = match rpc::get_keyset_ids(api_config, tenant_org_id.clone()).await {
        Ok(all_vpc_ids) => all_vpc_ids,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            return show_keysets_deprecated(json, api_config, tenant_org_id).await;
        }
        Err(e) => return Err(e),
    };
    let mut all_keysets = forgerpc::TenantKeySetList {
        keyset: Vec::with_capacity(all_ids.keyset_ids.len()),
    };
    for ids in all_ids.keyset_ids.chunks(page_size) {
        let keysets = rpc::get_keysets_by_ids(api_config, ids).await?;
        all_keysets.keyset.extend(keysets.keyset);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&all_keysets).unwrap());
    } else {
        convert_keysets_to_nice_table(all_keysets).printstd();
    }
    Ok(())
}

async fn show_keyset_details(
    id: String,
    json: bool,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let split_id = id.split('/').collect::<Vec<&str>>();
    if split_id.len() != 2 {
        return Err(CarbideCliError::GenericError(
            "Invalid format for Tenant KeySet ID".to_string(),
        ));
    }
    let identifier = forgerpc::TenantKeysetIdentifier {
        organization_id: split_id[0].to_string(),
        keyset_id: split_id[1].to_string(),
    };
    let keysets = match rpc::get_keysets_by_ids(api_config, &[identifier.clone()]).await {
        Ok(keysets) => keysets,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            rpc::get_keysets_deprecated(api_config, None, Some(identifier)).await?
        }
        Err(e) => return Err(e),
    };

    if keysets.keyset.len() != 1 {
        return Err(CarbideCliError::GenericError(
            "Unknown Tenant KeySet ID".to_string(),
        ));
    }

    let keysets = &keysets.keyset[0];

    if json {
        println!("{}", serde_json::to_string_pretty(keysets).unwrap());
    } else {
        println!(
            "{}",
            convert_keyset_to_nice_format(keysets).unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

fn convert_keysets_to_nice_table(keysets: forgerpc::TenantKeySetList) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row!["Id", "TenantOrg", "Version", "Keys",]);

    for keyset in keysets.keyset {
        table.add_row(row![
            keyset
                .keyset_identifier
                .clone()
                .unwrap_or_default()
                .keyset_id,
            keyset
                .keyset_identifier
                .clone()
                .unwrap_or_default()
                .organization_id,
            keyset.version,
            keyset
                .keyset_content
                .unwrap_or_default()
                .public_keys
                .len()
                .to_string(),
        ]);
    }

    table.into()
}

fn convert_keyset_to_nice_format(keyset: &forgerpc::TenantKeyset) -> CarbideCliResult<String> {
    let width = 25;
    let mut lines = String::new();

    let data = vec![
        (
            "ID",
            keyset
                .keyset_identifier
                .clone()
                .unwrap_or_default()
                .keyset_id,
        ),
        (
            "TENANT ORG",
            keyset
                .keyset_identifier
                .clone()
                .unwrap_or_default()
                .organization_id,
        ),
        ("VERSION", keyset.version.to_string()),
    ];

    for (key, value) in data {
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
    }

    writeln!(&mut lines, "{:<width$}: ", "KEYS")?;
    let width = 17;
    let keyset_content = keyset.keyset_content.clone().unwrap_or_default();
    if keyset_content.public_keys.is_empty() {
        writeln!(&mut lines, "\tNONE")?;
    } else {
        for key in keyset_content.public_keys {
            let data = vec![
                ("PUBLIC", key.public_key),
                ("COMMENT", key.comment.unwrap_or_default()),
            ];

            for (key, value) in data {
                writeln!(&mut lines, "\t{:<width$}: {}", key, value)?;
            }
            writeln!(
                &mut lines,
                "\t------------------------------------------------------------"
            )?;
        }
    }

    Ok(lines)
}

// TODO: remove when all sites updated to carbide-api with get_tenant_keyset_ids and get_tenant_keysets_by_ids implemented
async fn show_keysets_deprecated(
    json: bool,
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
) -> CarbideCliResult<()> {
    let keysets = rpc::get_keysets_deprecated(api_config, tenant_org_id, None).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&keysets).unwrap());
    } else {
        convert_keysets_to_nice_table(keysets).printstd();
    }
    Ok(())
}
