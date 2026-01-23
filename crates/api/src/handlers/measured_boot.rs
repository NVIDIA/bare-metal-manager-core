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

pub use ::rpc::{forge as rpc_forge, machine_discovery as rpc_md};
use carbide_uuid::machine::MachineId;
use db::attestation::secret_ak_pub;
use sqlx::PgConnection;
use tonic::Status;

use crate::{CarbideError, attestation as attest};

pub(crate) async fn create_attest_key_bind_challenge(
    txn: &mut PgConnection,
    attest_key_info: &rpc_md::AttestKeyInfo,
    machine_id: &MachineId,
) -> Result<rpc_forge::AttestKeyBindChallenge, Status> {
    let (matched, ek_pub_rsa) =
        attest::compare_pub_key_against_cert(txn, machine_id, attest_key_info.ek_pub.as_ref())
            .await?;
    if !matched {
        return Err(Status::from(CarbideError::AttestBindKeyError(
            "Certificate's public key did not match EK Pub Key".to_string(),
        )));
    }

    // generate a secret/credential
    let secret_bytes: [u8; 32] = rand::random();

    let (cli_cred_blob, cli_secret) =
        attest::cli_make_cred(ek_pub_rsa, &attest_key_info.ak_name, &secret_bytes)?;

    secret_ak_pub::insert(txn, &Vec::from(secret_bytes), &attest_key_info.ak_pub).await?;

    Ok(rpc_forge::AttestKeyBindChallenge {
        cred_blob: cli_cred_blob,
        encrypted_secret: cli_secret,
    })
}
