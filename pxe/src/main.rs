/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::{env, fmt::Debug, fmt::Display};

use ::rpc::forge;
use ::rpc::forge_tls_client::{self, ApiConfig, ForgeClientConfig};
use clap::Parser;
use forge_tls::client_config::ClientCert;
use rocket::figment::Figment;
use rocket::log::private::error;
use rocket::{
    fairing::AdHoc,
    form::Errors,
    fs::FileServer,
    http::Status,
    request::{self, FromRequest, Outcome},
    Request,
};
use rocket_dyn_templates::Template;
use rpc::forge::CloudInitInstructionsRequest;
use serde::Serialize;

mod logging;
mod machine_architecture;
mod routes;

#[derive(Debug)]
pub struct Machine {
    instructions: forge::CloudInitInstructions,
}

#[derive(Debug, Serialize)]
pub struct MachineInterface {
    architecture: Option<forge::MachineArchitecture>,
    interface_id: rocket::serde::uuid::Uuid,
}

#[derive(Clone)]
pub struct RuntimeConfig {
    internal_api_url: String,
    client_facing_api_url: String,
    pxe_url: String,
    forge_root_ca_path: String,
    server_cert_path: String,
    server_key_path: String,
}

pub enum RPCError<'a> {
    RequestError(tonic::Status),
    MissingClientConfig,
    MissingMachineId,
    InvalidBuildArch,
    MalformedMachineId(Errors<'a>),
    MalformedBuildArch(Errors<'a>),
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, default_value = "false", help = "Print version number and exit")]
    pub version: bool,

    #[clap(short, long, default_value = "static")]
    static_dir: String,
}

impl Debug for RPCError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self, f)
    }
}

impl Display for RPCError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::RequestError(err) => format!("Error making a carbide API request: {}", err),
                Self::MissingClientConfig =>
                    "Missing client configuration from server config (should not reach this case)"
                        .to_string(),
                Self::MissingMachineId =>
                    "Missing Machine Identifier (UUID) specified in URI parameter uuid".to_string(),
                Self::MalformedMachineId(err) => format!("Malformed Machine UUID: {}", err),
                RPCError::InvalidBuildArch =>
                    "Invalid build arch specified in URI parameter buildarch".to_string(),
                RPCError::MalformedBuildArch(err) => format!("Malformed build arch: {}", err),
            }
        )
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RuntimeConfig {
    type Error = RPCError<'r>;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Some(config) = request.rocket().state::<RuntimeConfig>() {
            Outcome::Success(config.clone())
        } else {
            error!("error in client returned none");
            Outcome::Failure((Status::BadRequest, RPCError::MissingClientConfig))
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Machine {
    type Error = RPCError<'r>;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let mut client = match request.rocket().state::<RuntimeConfig>() {
            Some(runtime_config) => {
                let api_config = ApiConfig::new(
                    &runtime_config.internal_api_url,
                    ForgeClientConfig::new(
                        runtime_config.forge_root_ca_path.clone(),
                        Some(ClientCert {
                            cert_path: runtime_config.server_cert_path.clone(),
                            key_path: runtime_config.server_key_path.clone(),
                        }),
                    ),
                );

                match forge_tls_client::ForgeTlsClient::new_and_connect(&api_config).await {
                    Ok(client) => client,
                    Err(err) => {
                        eprintln!(
                            "error connecting to forge api from pxe - {:?} - url: {:?}",
                            err, runtime_config.internal_api_url
                        );
                        return request::Outcome::Failure((
                            Status::BadRequest,
                            RPCError::MissingClientConfig,
                        ));
                    }
                }
            }
            None => {
                eprintln!("error in client returned none");
                return request::Outcome::Failure((
                    Status::BadRequest,
                    RPCError::MissingClientConfig,
                ));
            }
        };

        // Default to a proxied XFF header with the correct IP, and fallback to client IP if not
        let ip = match request.headers().get_one("X-Forwarded-For") {
            None => request.client_ip().map(|ip| ip.to_string()),
            Some(h) => Some(h.to_string()),
        };

        if let Some(ip) = ip {
            let request = tonic::Request::new(CloudInitInstructionsRequest { ip });

            let instructions = match client.get_cloud_init_instructions(request).await {
                Ok(response) => response.into_inner(),
                Err(err) => {
                    return request::Outcome::Failure((
                        Status::BadRequest,
                        RPCError::RequestError(err),
                    ));
                }
            };

            request::Outcome::Success(Machine { instructions })
        } else {
            eprintln!("error in client ip is none");
            request::Outcome::Failure((Status::BadRequest, RPCError::MissingMachineId))
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for MachineInterface {
    type Error = RPCError<'r>;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let architecture = match request.query_value::<&str>("buildarch") {
            Some(Ok(buildarch)) => match buildarch {
                "arm64" => Some(forge::MachineArchitecture::Arm),
                "x86_64" => Some(forge::MachineArchitecture::X86),
                arch => {
                    eprintln!("invalid architecture: {:#?}", arch);
                    return request::Outcome::Failure((
                        Status::BadRequest,
                        RPCError::InvalidBuildArch,
                    ));
                }
            },
            Some(Err(errs)) => {
                return request::Outcome::Failure((
                    Status::BadRequest,
                    RPCError::MalformedBuildArch(errs),
                ));
            }
            None => None,
        };
        let interface_id = match request.query_value::<rocket::serde::uuid::Uuid>("uuid") {
            Some(Ok(uuid)) => uuid,
            Some(Err(errs)) => {
                return request::Outcome::Failure((
                    Status::BadRequest,
                    RPCError::MalformedMachineId(errs),
                ));
            }
            None => {
                eprintln!("{:#?}", request.param::<rocket::serde::uuid::Uuid>(0));
                match request.param::<rocket::serde::uuid::Uuid>(0) {
                    Some(uuid) => match uuid {
                        Ok(uuid) => uuid,
                        Err(_) => {
                            return request::Outcome::Failure((
                                Status::BadRequest,
                                RPCError::MissingMachineId,
                            ));
                        }
                    },
                    None => {
                        return request::Outcome::Failure((
                            Status::BadRequest,
                            RPCError::MissingMachineId,
                        ));
                    }
                }
            }
        };

        request::Outcome::Success(Self {
            architecture,
            interface_id,
        })
    }
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let opts = Args::parse();
    if opts.version {
        println!("{}", forge_version::version!());
        return Ok(());
    }

    let static_path = std::path::Path::new(&opts.static_dir);

    if !&static_path.exists() {
        println!(
            "Static path {} does not exist. Creating directory",
            &static_path.display()
        );

        match std::fs::create_dir_all(static_path) {
            Ok(_) => println!("Directory {}, created", &static_path.display()),
            Err(e) => eprintln!("Could not create directory: {}", e),
        }
    }

    println!("Start carbide-pxe version {}", forge_version::version!());
    rocket::build()
        .mount("/api/v0/pxe", routes::ipxe::routes())
        .mount("/api/v0/cloud-init", routes::cloud_init::routes())
        .mount("/public", FileServer::from(opts.static_dir))
        .attach(logging::RequestLogger)
        .attach(Template::fairing())
        .attach(AdHoc::try_on_ignite(
            "Carbide API Config",
            |rocket| async move {
                match extract_params(rocket.figment()) {
                    Ok(config) => {
                        if std::path::Path::new(&config.forge_root_ca_path).exists() {
                            Ok(rocket.manage(config))
                        } else {
                            println!(
                                "path for forge_root_ca_path does not exist on disk: {}",
                                &config.forge_root_ca_path,
                            );

                            Err(rocket)
                        }
                    }
                    Err(err) => {
                        println!(
                            "An unexpected error occurred in carbide pxe server setup: {}",
                            err
                        );
                        Err(rocket)
                    }
                }
            },
        ))
        .ignite()
        .await?
        .launch()
        .await
}

fn extract_params(figment: &Figment) -> Result<RuntimeConfig, String> {
    Ok(RuntimeConfig {
        internal_api_url: figment
            .extract_inner::<String>("carbide_api_internal_url")
            .unwrap_or("https://carbide-api.forge-system.svc.cluster.local:1079".to_string()),
        client_facing_api_url: figment
            .extract_inner::<String>("carbide_api_url")
            .map_err(|_| "Could not extract carbide_api_url from config")?,
        pxe_url: figment
            .extract_inner::<String>("carbide_pxe_url")
            .map_err(|_| "Could not extract carbide_pxe_url from config")?,
        forge_root_ca_path: env::var("FORGE_ROOT_CAFILE_PATH")
            .map_err(|_| "Could not extract FORGE_ROOT_CAFILE_PATH from environment".to_string())?,
        server_cert_path: env::var("FORGE_CLIENT_CERT_PATH")
            .map_err(|_| "Could not extract FORGE_CLIENT_CERT_PATH from environment".to_string())?,
        server_key_path: env::var("FORGE_CLIENT_KEY_PATH")
            .map_err(|_| "Could not extract FORGE_CLIENT_KEY_PATH from environment".to_string())?,
    })
}
