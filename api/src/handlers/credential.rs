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

use ::rpc::forge as rpc;
use forge_secrets::credentials::{BmcCredentialType, CredentialKey, CredentialType, Credentials};
use mac_address::MacAddress;
use tonic::Response;

use crate::api::Api;
use crate::credentials::UpdateCredentials;
use crate::db::machine::Machine;
use crate::db::DatabaseError;
use crate::ib::DEFAULT_IB_FABRIC_NAME;
use crate::CarbideError;

/// Username for debug SSH access to DPU. Created by cloud-init on boot. Password in Vault.
const DPU_ADMIN_USERNAME: &str = "forge";

/// Username for the root BMC account.
const FORGE_ROOT_BMC_USERNAME: &str = "root";

pub(crate) async fn create_credential(
    api: &Api,
    request: tonic::Request<rpc::CredentialCreationRequest>,
) -> Result<tonic::Response<rpc::CredentialCreationResult>, tonic::Status> {
    crate::api::log_request_data(&request);
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
            return Err(tonic::Status::invalid_argument("Forge no longer maintains separate paths for Host and DPU site-wide BMC root credentials. This has been unified."));
        }
        rpc::CredentialType::SiteWideBmcRoot => {
            set_sitewide_bmc_root_credentials(api, password)
                .await
                .map_err(|e| {
                    CarbideError::GenericError(format!(
                        "Error setting Site Wide BMC Root credentials: {:?} ",
                        e
                    ))
                })?;
        }
        rpc::CredentialType::Ufm => {
            if let Some(username) = req.username {
                api.credential_provider
                    .set_credentials(
                        CredentialKey::UfmAuth {
                            fabric: DEFAULT_IB_FABRIC_NAME.to_string(),
                        },
                        Credentials::UsernamePassword {
                            username: username.clone(),
                            password: password.clone(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::GenericError(format!(
                            "Error setting credential for Ufm {}: {:?} ",
                            username.clone(),
                            e
                        ))
                    })?;
            } else {
                return Err(tonic::Status::invalid_argument("missing UFM Url"));
            }
        }
        rpc::CredentialType::DpuUefi => {
            if (api
                .credential_provider
                .get_credentials(CredentialKey::DpuUefi {
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
                    CredentialKey::DpuUefi {
                        credential_type: CredentialType::SiteDefault,
                    },
                    Credentials::UsernamePassword {
                        username: "".to_string(),
                        password: password.clone(),
                    },
                )
                .await
                .map_err(|e| {
                    CarbideError::GenericError(format!(
                        "Error setting credential for DPU UEFI: {:?} ",
                        e
                    ))
                })?
        }
        rpc::CredentialType::HostUefi => {
            if api
                .credential_provider
                .get_credentials(CredentialKey::HostUefi {
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
                    CredentialKey::HostUefi {
                        credential_type: CredentialType::SiteDefault,
                    },
                    Credentials::UsernamePassword {
                        username: "".to_string(),
                        password: password.clone(),
                    },
                )
                .await
                .map_err(|e| {
                    CarbideError::GenericError(format!(
                        "Error setting credential for Host UEFI: {e:?}"
                    ))
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
                    CredentialKey::HostRedfish {
                        credential_type: CredentialType::HostHardwareDefault { vendor },
                    },
                    Credentials::UsernamePassword { username, password },
                )
                .await
                .map_err(|e| {
                    CarbideError::GenericError(format!(
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
                    CredentialKey::DpuRedfish {
                        credential_type: CredentialType::DpuHardwareDefault,
                    },
                    Credentials::UsernamePassword { username, password },
                )
                .await
                .map_err(|e| {
                    CarbideError::GenericError(format!(
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

            set_bmc_root_credentials_by_mac(api, parsed_mac, password)
                .await
                .map_err(|e| {
                    CarbideError::GenericError(format!(
                        "Error setting Site Wide BMC Root credentials: {:?} ",
                        e
                    ))
                })?;
        }
        rpc::CredentialType::BmcForgeAdminByMacAddress => {
            // TODO: support credential creation for forge-admin
            return Err(tonic::Status::invalid_argument(
                "Forge does not support creating forge-admin credentials yet.",
            ));
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
                        CredentialKey::UfmAuth {
                            fabric: DEFAULT_IB_FABRIC_NAME.to_string(),
                        },
                        Credentials::UsernamePassword {
                            username: username.clone(),
                            password: "".to_string(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::GenericError(format!(
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
        rpc::CredentialType::RootBmcByMacAddress => {
            match req.mac_address {
                Some(mac_address) => {
                    let parsed_mac: MacAddress = mac_address
                        .parse::<MacAddress>()
                        .map_err(CarbideError::from)?;

                    // TODO: actually delete entry from vault instead of setting to empty string
                    set_bmc_root_credentials_by_mac(api, parsed_mac, "".to_string()).await?;
                }
                None => {
                    return Err(tonic::Status::invalid_argument(
                        "request does not specify mac address",
                    ));
                }
            }
        }
        rpc::CredentialType::HostBmc
        | rpc::CredentialType::Dpubmc
        | rpc::CredentialType::DpuUefi
        | rpc::CredentialType::HostUefi
        | rpc::CredentialType::HostBmcFactoryDefault
        | rpc::CredentialType::DpuBmcFactoryDefault
        | rpc::CredentialType::BmcForgeAdminByMacAddress => {
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

    let request = UpdateCredentials::try_from(request.into_inner()).map_err(CarbideError::from)?;
    crate::api::log_machine_id(&request.machine_id);

    Ok(request
        .update(api.credential_provider.as_ref())
        .await
        .map(Response::new)?)
}

pub(crate) async fn get_dpu_ssh_credential(
    api: &Api,
    request: tonic::Request<rpc::CredentialRequest>,
) -> Result<Response<rpc::CredentialResponse>, tonic::Status> {
    crate::api::log_request_data(&request);

    let query = request.into_inner().host_id;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_dpu_ssh_credential",
            e,
        ))
    })?;
    let machine_id = match Machine::find_by_query(&mut txn, &query)
        .await
        .map_err(CarbideError::from)?
    {
        Some(machine) => {
            crate::api::log_machine_id(machine.id());
            if !machine.is_dpu() {
                return Err(tonic::Status::not_found(format!(
                    "Searching for machine {} was found for '{query}', but it is not a DPU",
                    machine.id()
                )));
            }
            machine.id().clone()
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
    txn.rollback().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "rollback get_dpu_ssh_credential",
            e,
        ))
    })?;

    // Load credentials from Vault
    let credentials = api
        .credential_provider
        .get_credentials(CredentialKey::DpuSsh {
            machine_id: machine_id.to_string(),
        })
        .await
        .map_err(|err| match err.downcast::<vaultrs::error::ClientError>() {
            Ok(vaultrs::error::ClientError::APIError { code: 404, .. }) => {
                CarbideError::NotFoundError {
                    kind: "dpu-ssh-cred",
                    id: machine_id.to_string(),
                }
            }
            Ok(ce) => CarbideError::GenericError(format!("Vault error: {}", ce)),
            Err(err) => CarbideError::GenericError(format!(
                "Error getting SSH credentials for DPU: {:?}",
                err
            )),
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
        username: FORGE_ROOT_BMC_USERNAME.to_string(),
        password: password.clone(),
    };

    set_bmc_credentials(api, credential_key, credentials).await
}

async fn set_bmc_root_credentials_by_mac(
    api: &Api,
    bmc_mac_address: MacAddress,
    password: String,
) -> Result<(), CarbideError> {
    let credential_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
    };

    let credentials = Credentials::UsernamePassword {
        username: FORGE_ROOT_BMC_USERNAME.to_string(),
        password: password.clone(),
    };

    set_bmc_credentials(api, credential_key, credentials).await
}

async fn set_bmc_credentials(
    api: &Api,
    credential_key: CredentialKey,
    credentials: Credentials,
) -> Result<(), CarbideError> {
    api.credential_provider
        .set_credentials(credential_key, credentials)
        .await
        .map_err(|e| {
            CarbideError::GenericError(format!("Error setting credential for BMC: {:?} ", e))
        })
}
