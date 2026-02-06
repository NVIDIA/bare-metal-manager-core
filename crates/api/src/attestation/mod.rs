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

#[cfg(feature = "linux-build")]
pub mod measured_boot;
#[cfg(feature = "linux-build")]
#[cfg(test)]
pub use measured_boot::do_compare_pub_key_against_cert;
#[cfg(feature = "linux-build")]
pub use measured_boot::{
    cli_make_cred, compare_pub_key_against_cert, event_log_to_string, has_passed_attestation,
    verify_pcr_hash, verify_quote_state, verify_signature,
};

pub mod tpm_ca_cert;
use carbide_uuid::machine::MachineId;
use db::{ObjectFilter, Transaction};
use model::hardware_info::TpmEkCertificate;
use model::machine::machine_search_config::MachineSearchConfig;
use sqlx::{PgConnection, Pool, Postgres};
pub use tpm_ca_cert::{extract_ca_fields, match_insert_new_ek_cert_status_against_ca};

use crate::{CarbideError, CarbideResult};

pub async fn get_ek_cert_by_machine_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> CarbideResult<TpmEkCertificate> {
    // fetch machine from the db
    let machine = db::machine::find_one(
        txn,
        machine_id,
        MachineSearchConfig {
            include_dpus: true,
            ..MachineSearchConfig::default()
        },
    )
    .await?
    .ok_or_else(|| CarbideError::internal(format!("Machine with id {machine_id} not found.")))?;

    // obtain an ek cert
    let tpm_ek_cert = machine
        .hardware_info
        .as_ref()
        .ok_or_else(|| CarbideError::internal("Hardware Info not found.".to_string()))?
        .tpm_ek_certificate
        .as_ref()
        .ok_or_else(|| CarbideError::internal("TPM EK Certificate not found.".to_string()))?;

    Ok(tpm_ek_cert.clone())
}

pub async fn backfill_ek_cert_status_for_existing_machines(
    db_pool: &Pool<Postgres>,
) -> CarbideResult<()> {
    // get all machines that are not DPU
    // for each machine
    // - get hardware info and extract tpm ek cert
    // - call match_insert_new_ek_cert_status_against_ca()

    let mut txn = Transaction::begin(db_pool).await?;

    let machines: Vec<::carbide_uuid::machine::MachineId> =
        db::machine::find(&mut txn, ObjectFilter::All, MachineSearchConfig::default())
            .await?
            .iter()
            .map(|machine| machine.id)
            .collect();

    if !machines.is_empty() {
        let topologies =
            db::machine_topology::find_latest_by_machine_ids(&mut txn, &machines).await?;
        for topology in topologies {
            let (machine_id, topology) = topology;
            let tpm_ek_cert = &topology.topology().discovery_data.info.tpm_ek_certificate;

            if tpm_ek_cert.is_some() {
                tpm_ca_cert::match_insert_new_ek_cert_status_against_ca(
                    &mut txn,
                    tpm_ek_cert.as_ref().unwrap(),
                    &machine_id,
                )
                .await?;
            }
        }
    }

    txn.commit().await?;

    Ok(())
}
