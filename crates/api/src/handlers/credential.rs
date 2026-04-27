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
use carbide_nvlink_manager::DEFAULT_NMX_M_NAME;
use forge_secrets::credentials::{
    BgpCredentialType, BmcCredentialType, CredentialKey, CredentialType, Credentials,
};
use mac_address::MacAddress;
use model::ConfigValidationError;
use model::ib::DEFAULT_IB_FABRIC_NAME;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;
use crate::credentials::UpdateCredentials;
use crate::handlers::utils::convert_and_log_machine_id;

/// Default Username for the admin BMC account.
const DEFAULT_FORGE_ADMIN_BMC_USERNAME: &str = "root";

/// The maximum size that will be accepted in the underlying BGP config
/// on the DPU.  This was directly verified by checking the maximum accepted
/// by FRR on the DPU.  NVUE will silently accept seemingly any length,
/// but FRR reloads fail above this length.
pub const MAX_BGP_PASSWORD_LENGTH: usize = 80;

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
            return Err(CarbideError::InvalidArgument(
                "Forge no longer maintains separate paths for Host and DPU site-wide BMC root credentials. This has been unified.".into(),
            ).into());
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
                api.credential_manager
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
                return Err(CarbideError::InvalidArgument("missing UFM Url".to_string()).into());
            }
        }
        rpc::CredentialType::DpuUefi => {
            if (api
                .credential_manager
                .get_credentials(&CredentialKey::DpuUefi {
                    credential_type: CredentialType::SiteDefault,
                })
                .await)
                .is_ok_and(|result| result.is_some())
            {
                // TODO: support reset credential
                return Err(tonic::Status::already_exists(
                    "Not support to reset DPU UEFI credential",
                ));
            }
            api.credential_manager
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
                .credential_manager
                .get_credentials(&CredentialKey::HostUefi {
                    credential_type: CredentialType::SiteDefault,
                })
                .await
                .is_ok_and(|result| result.is_some())
            {
                // TODO: support reset credential
                return Err(tonic::Status::already_exists(
                    "Resetting the Host UEFI credentials in Vault is not supported",
                ));
            }
            api.credential_manager
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
                return Err(CarbideError::InvalidArgument("missing username".to_string()).into());
            };
            let Some(vendor) = req.vendor else {
                return Err(CarbideError::InvalidArgument("missing vendor".to_string()).into());
            };
            let vendor: bmc_vendor::BMCVendor = vendor.as_str().into();
            api.credential_manager
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
                return Err(CarbideError::InvalidArgument("missing username".to_string()).into());
            };
            api.credential_manager
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
                return Err(CarbideError::InvalidArgument("mac address".to_string()).into());
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
            return Err(CarbideError::InvalidArgument(
                "Forge does not support creating forge-admin credentials yet.".into(),
            )
            .into());
        }
        rpc::CredentialType::NmxM => {
            if let Some(username) = req.username {
                api.credential_manager
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
                return Err(CarbideError::InvalidArgument("missing username".to_string()).into());
            }
        }
        rpc::CredentialType::BgpSiteWideLeafPassword => {
            api.credential_manager
                .set_credentials(
                    &CredentialKey::Bgp {
                        credential_type: BgpCredentialType::SiteWideLeafPassword,
                    },
                    &Credentials::UsernamePassword {
                        username: "".to_string(),
                        password: if password.len() <= MAX_BGP_PASSWORD_LENGTH {
                            password
                        } else {
                            return Err(CarbideError::InvalidConfiguration(ConfigValidationError::InvalidValue(format!("BGP password length exceeds {MAX_BGP_PASSWORD_LENGTH} characters"))).into())
                        },
                    },
                )
                .await
                .map_err(|e| {
                    CarbideError::internal(format!("Error setting BGP credential: {e:?}"))
                })?;
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
                api.credential_manager
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
                return Err(CarbideError::InvalidArgument("missing UFM Url".to_string()).into());
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
                return Err(CarbideError::InvalidArgument(
                    "request does not specify mac address".into(),
                )
                .into());
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
        rpc::CredentialType::BgpSiteWideLeafPassword => {
            api.credential_manager
                .delete_credentials(&CredentialKey::Bgp {
                    credential_type: BgpCredentialType::SiteWideLeafPassword,
                })
                .await
                .map_err(|e| {
                    CarbideError::internal(format!("Error deleting BGP credential: {e:?}"))
                })?;
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
        .execute(api.credential_manager.as_ref())
        .await
        .map(Response::new)?)
}

/// As for now we only support UsernamePassword credentials type,
/// in future this function should support SessionToken if available
pub(crate) async fn get_bmc_credentals(
    api: &Api,
    request: tonic::Request<rpc::GetBmcCredentialsRequest>,
) -> Result<Response<rpc::GetBmcCredentialsResponse>, tonic::Status> {
    crate::api::log_request_data(&request);

    let req = request.into_inner();

    let bmc_mac_address: mac_address::MacAddress = req
        .mac_addr
        .parse()
        .map_err(CarbideError::MacAddressParseError)?;

    let credentials = api
        .credential_manager
        .get_credentials(&CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
        })
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?
        .ok_or_else(|| CarbideError::internal("missing credentials".to_string()))?;

    let (username, password) = match credentials {
        Credentials::UsernamePassword { username, password } => (username, password),
    };

    Ok(Response::new(rpc::GetBmcCredentialsResponse {
        credentials: Some(rpc::BmcCredentials {
            r#type: Some(rpc::bmc_credentials::Type::UsernamePassword(
                rpc::UsernamePassword { username, password },
            )),
        }),
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

    api.credential_manager
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
    api.credential_manager
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
