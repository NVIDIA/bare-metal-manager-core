use std::io::BufWriter;

use serde::{Deserialize, Serialize};
use thrussh_keys::{key, write_public_key_base64};
use uuid::Uuid;

use console::ConsoleError;
use rpc::forge::v0 as rpc;

use crate::ipmi::IpmiInfo;

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

fn key_to_string(pubkey: &key::PublicKey) -> Result<String, ConsoleError> {
    let mut buf = BufWriter::new(Vec::new());
    write_public_key_base64(&mut buf, pubkey)?;
    let bytes = buf
        .into_inner()
        .map_err(|x| ConsoleError::GenericError(x.to_string()))?;
    String::from_utf8(bytes).map_err(ConsoleError::from)
}

pub fn validate_user_test(
    _user: &str,
    _pubkey: &key::PublicKey,
) -> Result<UserRoles, ConsoleError> {
    Ok(UserRoles::Administrator)
}

pub fn validate_user(user: &str, pubkey: &key::PublicKey) -> Result<UserRoles, ConsoleError> {
    use self::rpc::{SshKeyValidationRequest, SshKeyValidationResponse};

    let pubkey = key_to_string(pubkey)?
        .lines()
        .collect::<Vec<&str>>()
        .join("");

    let user = String::from(user);
    let api_endpoint = crate::CONFIG.read().unwrap().api_endpoint.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    tokio::task::spawn_blocking(move || {
        tokio::spawn(async move {
            let response: Result<SshKeyValidationResponse, &str> =
                match rpc::forge_client::ForgeClient::connect(api_endpoint).await {
                    Ok(mut client) => {
                        let request = tonic::Request::new(SshKeyValidationRequest { user, pubkey });

                        client
                            .validate_user_ssh_key(request)
                            .await
                            .map(|response| response.into_inner())
                            .map_err(|error| {
                                log::error!("unable to authenticate user: {:?}", error);
                                "Failed to authenticate user."
                            })
                    }
                    Err(err) => {
                        log::error!("unable to connect to Carbide API: {:?}", err);
                        Err("Server is down. Try again after sometime.")
                    }
                };
            let _ = tx.send(response).await;
        });
    });

    futures::executor::block_on(async {
        match rx.recv().await {
            Some(x) => match x {
                Ok(a) => {
                    if a.is_authenticated {
                        return UserRoles::from_i32(a.role).ok_or_else(|| {
                            ConsoleError::GenericError("Role parsing failed".to_string())
                        });
                    }

                    Err(ConsoleError::GenericError(
                        "Authentication failed.".to_string(),
                    ))
                }

                Err(e) => Err(ConsoleError::GenericError(e.to_string())),
            },
            None => Err(ConsoleError::GenericError(
                "Error getting data from sender.".to_string(),
            )),
        }
    })
}

pub fn get_bmc_metadata(machine_id: Uuid, role: UserRoles) -> Result<IpmiInfo, ConsoleError> {
    use self::rpc::{BmcMetaDataRequest, BmcMetaDataResponse};

    let api_endpoint = crate::CONFIG.read().unwrap().api_endpoint.clone();
    let response: Result<BmcMetaDataResponse, ConsoleError> = futures::executor::block_on(async {
        match rpc::forge_client::ForgeClient::connect(api_endpoint).await {
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
        }
    });

    let response = response?;
    Ok(IpmiInfo {
        ip: response.ip.parse()?,
        user: response.user,
        password: response.password,
    })
}
