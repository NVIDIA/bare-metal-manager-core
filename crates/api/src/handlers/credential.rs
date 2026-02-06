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

use std::fs::File;
use std::io::Write;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use forge_secrets::credentials::{BmcCredentialType, CredentialKey, CredentialType, Credentials};
use mac_address::MacAddress;
use model::ib::DEFAULT_IB_FABRIC_NAME;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;
use crate::credentials::UpdateCredentials;
use crate::handlers::utils::convert_and_log_machine_id;

/// Username for debug SSH access to DPU. Created by cloud-init on boot. Password in Vault.
const DPU_ADMIN_USERNAME: &str = "forge";

/// Default Username for the admin BMC account.
const DEFAULT_FORGE_ADMIN_BMC_USERNAME: &str = "root";

pub const DEFAULT_NMX_M_NAME: &str = "forge-nmx-m";

pub(crate) async fn create_credential(
    api: &Api,
    request: tonic::Request<rpc::CredentialCreationRequest>,
) -> Result<tonic::Response<rpc::CredentialCreationResult>, tonic::Status> {
    // Do not log_request_data as credentials contain sensitive information
    // crate::api::log_request_data(&request);

    let req = request.into_inner();
    let password = req.password;

    let credential_type = rpc::CredentialType::try_from(req.credential_type).map_err(|_| {
        CarbideError::NotFoundError {
            kind: "credential_type",
            id: req.credential_type.to_string(),
        }
    })?;

    match credential_type {
        rpc::CredentialType::HostBmc | rpc::CredentialType::Dpubmc => {
            return Err(tonic::Status::invalid_argument(
                "Forge no longer maintains separate paths for Host and DPU site-wide BMC root credentials. This has been unified.",
            ));
        }
        rpc::CredentialType::SiteWideBmcRoot => {
            set_sitewide_bmc_root_credentials(api, password)
                .await
                .map_err(|e| {
                    CarbideError::internal(format!(
                        "Error setting Site Wide BMC Root credentials: {e:?} "
                    ))
                })?;
        }
        rpc::CredentialType::Ufm => {
            if let Some(username) = req.username {
                api.credential_provider
                    .set_credentials(
                        &CredentialKey::UfmAuth {
                            fabric: DEFAULT_IB_FABRIC_NAME.to_string(),
                        },
                        &Credentials::UsernamePassword {
                            username: username.clone(),
                            password: password.clone(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::internal(format!(
                            "Error setting credential for Ufm {}: {:?} ",
                            username.clone(),
                            e
                        ))
                    })?;
            } else if req.username.is_none() && password.is_empty() && req.vendor.is_some() {
                write_ufm_certs(api, req.vendor.unwrap_or_default()).await?;
            } else {
                return Err(tonic::Status::invalid_argument("missing UFM Url"));
            }
        }
        rpc::CredentialType::DpuUefi => {
            if (api
                .credential_provider
                .get_credentials(&CredentialKey::DpuUefi {
                    credential_type: CredentialType::SiteDefault,
                })
                .await)
                .is_ok()
            {
                // TODO: support reset credential
                return Err(tonic::Status::already_exists(
                    "Not support to reset DPU UEFI credential",
                ));
            }
            api.credential_provider
                .set_credentials(
                    &CredentialKey::DpuUefi {
                        credential_type: CredentialType::SiteDefault,
                    },
                    &Credentials::UsernamePassword {
                        username: "".to_string(),
                        password: password.clone(),
                    },
                )
                .await
                .map_err(|e| {
                    CarbideError::internal(format!("Error setting credential for DPU UEFI: {e:?} "))
                })?
        }
        rpc::CredentialType::HostUefi => {
            if api
                .credential_provider
                .get_credentials(&CredentialKey::HostUefi {
                    credential_type: CredentialType::SiteDefault,
                })
                .await
                .is_ok()
            {
                // TODO: support reset credential
                return Err(tonic::Status::already_exists(
                    "Resetting the Host UEFI credentials in Vault is not supported",
                ));
            }
            api.credential_provider
                .set_credentials(
                    &CredentialKey::HostUefi {
                        credential_type: CredentialType::SiteDefault,
                    },
                    &Credentials::UsernamePassword {
                        username: "".to_string(),
                        password: password.clone(),
                    },
                )
                .await
                .map_err(|e| {
                    CarbideError::internal(format!("Error setting credential for Host UEFI: {e:?}"))
                })?
        }
        rpc::CredentialType::HostBmcFactoryDefault => {
            let Some(username) = req.username else {
                return Err(tonic::Status::invalid_argument("missing username"));
            };
            let Some(vendor) = req.vendor else {
                return Err(tonic::Status::invalid_argument("missing vendor"));
            };
            let vendor: bmc_vendor::BMCVendor = vendor.as_str().into();
            api.credential_provider
                .set_credentials(
                    &CredentialKey::HostRedfish {
                        credential_type: CredentialType::HostHardwareDefault { vendor },
                    },
                    &Credentials::UsernamePassword { username, password },
                )
                .await
                .map_err(|e| {
                    CarbideError::internal(format!(
                        "Error setting Host factory default credential: {e:?}"
                    ))
                })?
        }
        rpc::CredentialType::DpuBmcFactoryDefault => {
            let Some(username) = req.username else {
                return Err(tonic::Status::invalid_argument("missing username"));
            };
            api.credential_provider
                .set_credentials(
                    &CredentialKey::DpuRedfish {
                        credential_type: CredentialType::DpuHardwareDefault,
                    },
                    &Credentials::UsernamePassword { username, password },
                )
                .await
                .map_err(|e| {
                    CarbideError::internal(format!(
                        "Error setting DPU factory default credential: {e:?}"
                    ))
                })?
        }
        rpc::CredentialType::RootBmcByMacAddress => {
            let Some(mac_address) = req.mac_address else {
                return Err(tonic::Status::invalid_argument("mac address"));
            };

            let parsed_mac: MacAddress = mac_address
                .parse::<MacAddress>()
                .map_err(CarbideError::from)?;

            set_bmc_root_credentials_by_mac(api, parsed_mac, password, req.username)
                .await
                .map_err(|e| {
                    CarbideError::internal(format!(
                        "Error setting Site Wide BMC Root credentials: {e:?} "
                    ))
                })?;
        }
        rpc::CredentialType::BmcForgeAdminByMacAddress => {
            // TODO: support credential creation for forge-admin
            return Err(tonic::Status::invalid_argument(
                "Forge does not support creating forge-admin credentials yet.",
            ));
        }
        rpc::CredentialType::NmxM => {
            if let Some(username) = req.username {
                api.credential_provider
                    .set_credentials(
                        &CredentialKey::NmxM {
                            nmxm_id: DEFAULT_NMX_M_NAME.to_string(),
                        },
                        &Credentials::UsernamePassword {
                            username: username.clone(),
                            password: password.clone(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::internal(format!(
                            "Error setting credential for NmxM {}: {:?} ",
                            username.clone(),
                            e
                        ))
                    })?;
            } else {
                return Err(tonic::Status::invalid_argument("missing username"));
            }
        }
    };

    Ok(Response::new(rpc::CredentialCreationResult {}))
}

pub(crate) async fn delete_credential(
    api: &Api,
    request: tonic::Request<rpc::CredentialDeletionRequest>,
) -> Result<tonic::Response<rpc::CredentialDeletionResult>, tonic::Status> {
    crate::api::log_request_data(&request);
    let req = request.into_inner();

    let credential_type = rpc::CredentialType::try_from(req.credential_type).map_err(|_| {
        CarbideError::NotFoundError {
            kind: "credential_type",
            id: req.credential_type.to_string(),
        }
    })?;

    match credential_type {
        rpc::CredentialType::Ufm => {
            if let Some(username) = req.username {
                api.credential_provider
                    .set_credentials(
                        &CredentialKey::UfmAuth {
                            fabric: DEFAULT_IB_FABRIC_NAME.to_string(),
                        },
                        &Credentials::UsernamePassword {
                            username: username.clone(),
                            password: "".to_string(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::internal(format!(
                            "Error deleting credential for Ufm {}: {:?} ",
                            username.clone(),
                            e
                        ))
                    })?;
            } else {
                return Err(tonic::Status::invalid_argument("missing UFM Url"));
            }
        }
        rpc::CredentialType::SiteWideBmcRoot => {
            // TODO: actually delete entry from vault instead of setting to empty string
            set_sitewide_bmc_root_credentials(api, "".to_string()).await?;
        }
        rpc::CredentialType::RootBmcByMacAddress => match req.mac_address {
            Some(mac_address) => {
                let parsed_mac: MacAddress = mac_address
                    .parse::<MacAddress>()
                    .map_err(CarbideError::from)?;

                delete_bmc_root_credentials_by_mac(api, parsed_mac).await?;
            }
            None => {
                return Err(tonic::Status::invalid_argument(
                    "request does not specify mac address",
                ));
            }
        },
        rpc::CredentialType::HostBmc
        | rpc::CredentialType::Dpubmc
        | rpc::CredentialType::DpuUefi
        | rpc::CredentialType::HostUefi
        | rpc::CredentialType::HostBmcFactoryDefault
        | rpc::CredentialType::DpuBmcFactoryDefault
        | rpc::CredentialType::BmcForgeAdminByMacAddress
        | rpc::CredentialType::NmxM => {
            // Not support delete credential for these types
        }
    };

    Ok(Response::new(rpc::CredentialDeletionResult {}))
}

pub(crate) async fn update_machine_credentials(
    api: &Api,
    request: tonic::Request<rpc::MachineCredentialsUpdateRequest>,
) -> Result<Response<rpc::MachineCredentialsUpdateResponse>, tonic::Status> {
    // Note that we don't log the request here via `log_request_data`.
    // Doing that would make credentials show up in the log stream
    tracing::Span::current().record("request", "MachineCredentialsUpdateRequest { }");

    let request = request.into_inner();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    let mac_address = match request.mac_address {
        Some(v) => Some(v.parse().map_err(|_| {
            CarbideError::from(RpcDataConversionError::InvalidMacAddress(
                "mac_address".into(),
            ))
        })?),
        None => None,
    };

    let update = UpdateCredentials {
        machine_id,
        mac_address,
        credentials: request.credentials,
    };

    Ok(update
        .execute(api.credential_provider.as_ref())
        .await
        .map(Response::new)?)
}

pub(crate) async fn get_dpu_ssh_credential(
    api: &Api,
    request: tonic::Request<rpc::CredentialRequest>,
) -> Result<Response<rpc::CredentialResponse>, tonic::Status> {
    crate::api::log_request_data(&request);

    let query = request.into_inner().host_id;

    let mut txn = api.txn_begin().await?;

    let machine_id = match db::machine::find_by_query(&mut txn, &query).await? {
        Some(machine) => {
            crate::api::log_machine_id(&machine.id);
            if !machine.is_dpu() {
                return Err(tonic::Status::not_found(format!(
                    "Searching for machine {} was found for '{query}', but it is not a DPU",
                    &machine.id
                )));
            }
            machine.id
        }
        None => {
            return Err(CarbideError::NotFoundError {
                kind: "machine",
                id: query,
            }
            .into());
        }
    };

    // We don't need this transaction
    txn.rollback().await?;

    // Load credentials from Vault
    let credentials = api
        .credential_provider
        .get_credentials(&CredentialKey::DpuSsh { machine_id })
        .await
        .map_err(|err| CarbideError::internal(format!("Secret manager error: {err}")))?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "dpu-ssh-cred",
            id: machine_id.to_string(),
        })?;

    let (username, password) = match credentials {
        Credentials::UsernamePassword { username, password } => (username, password),
    };

    // UpdateMachineCredentials only allows a single account currently so warn if it's
    // not the correct one.
    if username != DPU_ADMIN_USERNAME {
        tracing::warn!(
            expected = DPU_ADMIN_USERNAME,
            found = username,
            "Unexpected username in Vault"
        );
    }

    Ok(Response::new(rpc::CredentialResponse {
        username,
        password,
    }))
}

async fn set_sitewide_bmc_root_credentials(
    api: &Api,
    password: String,
) -> Result<(), CarbideError> {
    let credential_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::SiteWideRoot,
    };

    let credentials = Credentials::UsernamePassword {
        // we no longer set a site-wide bmc username
        username: "".to_string(),
        password: password.clone(),
    };

    set_bmc_credentials(api, &credential_key, &credentials).await
}

pub(crate) async fn delete_bmc_root_credentials_by_mac(
    api: &Api,
    bmc_mac_address: MacAddress,
) -> Result<(), CarbideError> {
    let credential_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
    };

    api.credential_provider
        .delete_credentials(&credential_key)
        .await
        .map_err(|e| CarbideError::internal(format!("Error deleting credential for BMC: {e:?} ")))
}

async fn set_bmc_root_credentials_by_mac(
    api: &Api,
    bmc_mac_address: MacAddress,
    password: String,
    username: Option<String>,
) -> Result<(), CarbideError> {
    let credential_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
    };

    let credentials = Credentials::UsernamePassword {
        username: username.unwrap_or_else(|| DEFAULT_FORGE_ADMIN_BMC_USERNAME.to_string()),
        password: password.clone(),
    };

    set_bmc_credentials(api, &credential_key, &credentials).await
}

async fn set_bmc_credentials(
    api: &Api,
    credential_key: &CredentialKey,
    credentials: &Credentials,
) -> Result<(), CarbideError> {
    api.credential_provider
        .set_credentials(credential_key, credentials)
        .await
        .map_err(|e| CarbideError::internal(format!("Error setting credential for BMC: {e:?} ")))
}

pub async fn write_ufm_certs(api: &Api, fabric: String) -> Result<(), CarbideError> {
    const CERT_PATH: &str = "/var/run/secrets";

    // ttl can be limited by vault, so final value can be different
    // alternative names should match vault`s `allowed_domains` parameter
    // See: forged:bases/argo-workflows/workflows/vault/configure-vault.yaml
    let ttl = "365d".to_string();
    let alt_names = if let Some(value) = &api.runtime_config.initial_domain_name {
        format!("{fabric}.ufm.forge, {fabric}.ufm.{value}")
    } else {
        format!("{fabric}.ufm.forge")
    };

    let certificate = api
        .certificate_provider
        .get_certificate(fabric.as_str(), Some(alt_names), Some(ttl))
        .await
        .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?;

    let mut cert_filename = format!("{CERT_PATH}/{fabric}-ufm-ca-intermediate.crt");
    let mut cert_file = File::create(cert_filename.clone()).map_err(|e| {
        CarbideError::internal(format!("Could not create: {cert_filename} err: {e:?}"))
    })?;
    cert_file
        .write_all(certificate.issuing_ca.as_slice())
        .map_err(|e| {
            CarbideError::internal(format!(
                "Failed to write certificate to: {cert_filename} error: {e:?}"
            ))
        })?;

    cert_filename = format!("{CERT_PATH}/{fabric}-ufm-server.key");
    cert_file = File::create(cert_filename.clone()).map_err(|e| {
        CarbideError::internal(format!("Could not create: {cert_filename} err: {e:?}"))
    })?;
    cert_file
        .write_all(certificate.private_key.as_slice())
        .map_err(|e| {
            CarbideError::internal(format!(
                "Failed to write certificate to: {cert_filename} error: {e:?}"
            ))
        })?;

    cert_filename = format!("{CERT_PATH}/{fabric}-ufm-server.crt");
    cert_file = File::create(cert_filename.clone()).map_err(|e| {
        CarbideError::internal(format!("Could not create: {cert_filename} err: {e:?}"))
    })?;
    cert_file
        .write_all(certificate.public_key.as_slice())
        .map_err(|e| {
            CarbideError::internal(format!(
                "Failed to write certificate to: {cert_filename} error: {e:?}"
            ))
        })?;

    Ok(())
}

pub(crate) async fn renew_machine_certificate(
    api: &Api,
    request: Request<rpc::MachineCertificateRenewRequest>,
) -> Result<Response<rpc::MachineCertificateResult>, Status> {
    if let Some(machine_identity) = request
        .extensions()
        .get::<crate::auth::AuthContext>()
        // XXX: Does a machine's certificate resemble a service's
        // certificate enough for this to work?
        .and_then(|auth_context| auth_context.get_spiffe_machine_id())
    {
        let certificate = api
            .certificate_provider
            .get_certificate(machine_identity, None, None)
            .await
            .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?;

        return Ok(Response::new(rpc::MachineCertificateResult {
            machine_certificate: Some(certificate.into()),
        }));
    }

    Err(CarbideError::ClientCertificateError("no client certificate presented?".to_string()).into())
}
