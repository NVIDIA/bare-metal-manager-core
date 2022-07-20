#[cfg(not(test))]
use log::error;
#[cfg(test)]
use std::println as error;

use self::rpc::{
    BmcMetaDataRequest, BmcMetaDataResponse, SshKeyValidationRequest, SshKeyValidationResponse,
    UserRoles,
};
use crate::ipmi::IpmiInfo;
use crate::CONFIG;
use console::ConsoleError;
use futures::executor::block_on;
use rpc::forge::v0 as rpc;
use serde::{Deserialize, Serialize};
use std::io::BufWriter;
use thrussh_keys::{key, write_public_key_base64};
use tokio::sync::mpsc::channel;
use uuid::Uuid;

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
    Ok(String::from_utf8(bytes).map_err(ConsoleError::from)?)
}

// Validates user and returns role.
#[cfg(test)]
pub fn validate_user(user: &str, pubkey: &key::PublicKey) -> Result<UserRoles, ConsoleError> {
    Ok(UserRoles::Administrator)
}

#[cfg(not(test))]
pub fn validate_user(user: &str, pubkey: &key::PublicKey) -> Result<UserRoles, ConsoleError> {
    let pubkey = key_to_string(pubkey)?
        .lines()
        .collect::<Vec<&str>>()
        .join("");

    let user = String::from(user);
    let api_endpoint = CONFIG.read().unwrap().api_endpoint.clone();
    let (tx, mut rx) = channel(10);
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
                                error!("unable to authenticate user: {:?}", error);
                                "Failed to authenticate user."
                            })
                    }
                    Err(err) => {
                        error!("unable to connect to Carbide API: {:?}", err);
                        Err("Server is down. Try again after sometime.")
                    }
                };
            let _ = tx.send(response).await;
        });
    });

    block_on(async {
        match rx.recv().await {
            Some(x) => match x {
                Ok(a) => {
                    if a.is_authenticated {
                        return Ok(UserRoles::from_i32(a.role).ok_or(
                            ConsoleError::GenericError("Role parsing failed".to_string()),
                        )?);
                    }

                    return Err(ConsoleError::GenericError(
                        "Authentication failed.".to_string(),
                    ));
                }

                Err(e) => {
                    return Err(ConsoleError::GenericError(e.to_string()));
                }
            },
            None => {
                return Err(ConsoleError::GenericError(
                    "Error getting data from sender.".to_string(),
                ));
            }
        }
    })
}

#[cfg(test)]
pub fn get_bmc_metadata(_machine_id: Uuid, _role: UserRoles) -> Result<IpmiInfo, ConsoleError> {
    Ok(IpmiInfo {
        ip: "127.0.0.2".parse()?,
        user: "temp".to_string(),
        password: "temp".to_string(),
    })
}

#[cfg(not(test))]
// Takes role and finds first user as per role and returns it.
pub fn get_bmc_metadata(machine_id: Uuid, role: UserRoles) -> Result<IpmiInfo, ConsoleError> {
    let api_endpoint = CONFIG.read().unwrap().api_endpoint.clone();
    let response: Result<BmcMetaDataResponse, ConsoleError> = block_on(async {
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
    })
    .map_err(|x| x.into());

    let response = response?;
    Ok(IpmiInfo {
        ip: response.ip.parse()?,
        user: response.user,
        password: response.password,
    })
}
