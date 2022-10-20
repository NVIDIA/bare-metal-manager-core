/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::io::BufWriter;

use serde::{Deserialize, Serialize};
use thrussh_keys::key::PublicKey;
use thrussh_keys::write_public_key_base64;
use tonic::async_trait;
use uuid::Uuid;

use ::rpc::forge as rpc;
use ::rpc::forge::BmcMetaDataResponse;
use console::ConsoleError;

use crate::ConsoleContext;

use self::rpc::BmcMetaDataRequest;
use self::rpc::SshKeyValidationRequest;
use self::rpc::UserRoles;

#[derive(Serialize, Deserialize, Debug)]
struct BMCCred {
    user: String,
    password: String,
    role: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthData {
    role: String,
    keys: Vec<String>,
}

fn key_to_string(pubkey: &PublicKey) -> Result<String, ConsoleError> {
    let mut buf = BufWriter::new(Vec::new());
    write_public_key_base64(&mut buf, pubkey)?;
    let bytes = buf
        .into_inner()
        .map_err(|x| ConsoleError::GenericError(x.to_string()))?;
    String::from_utf8(bytes).map_err(ConsoleError::from)
}

#[async_trait]
pub trait UserValidator {
    async fn validate_user(
        &self,
        user: &str,
        public_key: &PublicKey,
        console_context: &ConsoleContext,
    ) -> Result<UserRoles, ConsoleError>;
}

#[derive(Clone, Debug)]
pub struct RealUserValidator {}

#[async_trait]
impl UserValidator for RealUserValidator {
    async fn validate_user(
        &self,
        user: &str,
        public_key: &PublicKey,
        console_context: &ConsoleContext,
    ) -> Result<UserRoles, ConsoleError> {
        let pubkey = key_to_string(public_key)?
            .lines()
            .collect::<Vec<&str>>()
            .join("");

        let user = String::from(user);
        let api_endpoint = console_context.api_endpoint.clone();

        match rpc::forge_client::ForgeClient::connect(api_endpoint).await {
            Ok(mut client) => {
                let request = tonic::Request::new(SshKeyValidationRequest { user, pubkey });

                match client
                    .validate_user_ssh_key(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| {
                        log::error!("unable to authenticate user: {:?}", error);
                        "Failed to authenticate user."
                    }) {
                    Ok(a) => {
                        if a.is_authenticated {
                            UserRoles::from_i32(a.role).ok_or_else(|| {
                                ConsoleError::GenericError("Role parsing failed".to_string())
                            })
                        } else {
                            Err(ConsoleError::GenericError(
                                "Authentication failed.".to_string(),
                            ))
                        }
                    }
                    Err(e) => Err(ConsoleError::GenericError(e.to_string())),
                }
            }
            Err(err) => {
                log::error!("unable to connect to Carbide API: {:?}", err);
                Err(ConsoleError::GenericError(
                    "Server is down. Try again after sometime.".to_string(),
                ))
            }
        }
    }
}

pub async fn get_bmc_metadata(
    machine_id: Uuid,
    role: UserRoles,
    api_endpoint: String,
) -> Result<BmcMetaDataResponse, ConsoleError> {
    let response = match rpc::forge_client::ForgeClient::connect(api_endpoint).await {
        Ok(mut client) => {
            let request = tonic::Request::new(BmcMetaDataRequest {
                machine_id: Some(machine_id.into()),
                request_type: rpc::BmcRequestType::Ipmi as i32,
                role: role as i32,
            });

            client
                .get_bmc_meta_data(request)
                .await
                .map(|response| response.into_inner())
                .map_err(ConsoleError::from)
        }
        Err(err) => Err(ConsoleError::from(err)),
    };

    let response = response?;
    Ok(response)
}
