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
use std::{env, fmt::Debug, fmt::Display};

use clap::Parser;
use rocket::figment::Figment;
use rocket::{
    fairing::AdHoc,
    form::Errors,
    fs::FileServer,
    http::Status,
    request::{self, FromRequest, Outcome},
    Request,
};
use rocket_dyn_templates::Template;
use serde::Serialize;

use ::rpc::forge;
use ::rpc::forge::forge_client::ForgeClient;
use ::rpc::forge::DomainSearchQuery;
use ::rpc::forge::InterfaceSearchQuery;

use crate::artifacts::ArtifactConfig;

mod artifacts;
mod machine_architecture;
mod routes;

#[derive(Debug)]
pub struct Machine {
    architecture: Option<forge::MachineArchitecture>,
    interface: forge::MachineInterface,
    domain: forge::Domain,
    machine: Option<forge::Machine>,
}

#[derive(Clone)]
pub struct RuntimeConfig {
    api_url: String,
    pxe_url: String,
    ntp_server: String,
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
    #[clap(short, long, default_value = "static")]
    static_dir: String,
}

impl Serialize for Machine {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_newtype_struct("Machine", &self.interface)
    }
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
            eprintln!("error in client returned none");
            Outcome::Failure((Status::BadRequest, RPCError::MissingClientConfig))
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Machine {
    type Error = RPCError<'r>;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let buildarch = match request.query_value::<&str>("buildarch") {
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
        let uuid = match request.query_value::<rocket::serde::uuid::Uuid>("uuid") {
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
                    Some(uuid) => uuid.unwrap(),
                    None => {
                        return request::Outcome::Failure((
                            Status::BadRequest,
                            RPCError::MissingMachineId,
                        ));
                    }
                }
            }
        };

        let mut client = match request.rocket().state::<RuntimeConfig>() {
            Some(url) => match ForgeClient::connect(url.api_url.clone()).await {
                Ok(client) => client,
                Err(_err) => {
                    eprintln!("error in connect - {:?} - url: {:?}", _err, url.api_url);
                    return request::Outcome::Failure((
                        Status::BadRequest,
                        RPCError::MissingClientConfig,
                    ));
                }
            },
            None => {
                eprintln!("error in client returned none");
                return request::Outcome::Failure((
                    Status::BadRequest,
                    RPCError::MissingClientConfig,
                ));
            }
        };

        let request = tonic::Request::new(InterfaceSearchQuery {
            id: Some(forge::Uuid {
                value: uuid.to_string(),
            }),
        });

        let interface = match client.find_interfaces(request).await {
            // TODO(baz): fix this blatantly ugly remove(0) w/o checking the size
            Ok(response) => response.into_inner().interfaces.remove(0),
            Err(err) => {
                return request::Outcome::Failure((
                    Status::BadRequest,
                    RPCError::RequestError(err),
                ));
            }
        };

        let request = tonic::Request::new(DomainSearchQuery {
            id: interface.domain_id.clone(),
            name: None,
        });

        let domain = match client.find_domain(request).await {
            // TODO(baz): fix this blatantly ugly remove(0) w/o checking the size
            Ok(response) => response.into_inner().domains.remove(0),
            Err(err) => {
                return request::Outcome::Failure((
                    Status::BadRequest,
                    RPCError::RequestError(err),
                ));
            }
        };

        match interface.machine_id.clone() {
            None => request::Outcome::Success(Machine {
                architecture: buildarch,
                interface,
                domain,
                machine: None,
            }),
            Some(machine_id) => {
                let request = tonic::Request::new(machine_id);
                match client.get_machine(request).await {
                    Ok(machine) => request::Outcome::Success(Machine {
                        architecture: buildarch,
                        interface,
                        domain,
                        machine: Some(machine.into_inner()),
                    }),
                    Err(err) => {
                        request::Outcome::Failure((Status::BadRequest, RPCError::RequestError(err)))
                    }
                }
            }
        }
    }
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let opts = Args::parse();

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

    let configuration_file_path =
        env::var("ARTIFACT_CONFIG").unwrap_or_else(|_| "artifacts.json".to_string());
    let artifact_configuration = ArtifactConfig::from_config_file(configuration_file_path)
        .expect("unable to parse artifact configuration file?");
    println!("Artifact config parsed: {}", &artifact_configuration);

    if let Err(error) = artifact_configuration.validate_artifacts(static_path).await {
        eprintln!("Error validating artifacts. Error: {:?}", error);
    }

    rocket::build()
        .mount("/api/v0/pxe", routes::ipxe::routes())
        .mount("/api/v0/cloud-init", routes::cloud_init::routes())
        .mount("/public", FileServer::from(opts.static_dir))
        .attach(Template::fairing())
        .attach(AdHoc::try_on_ignite(
            "Carbide API Config",
            |rocket| async move {
                match extract_params(rocket.figment()) {
                    Ok(config) => Ok(rocket.manage(RuntimeConfig {
                        api_url: config.api_url,
                        pxe_url: config.pxe_url,
                        ntp_server: config.ntp_server,
                    })),
                    Err(err) => {
                        println!("An unexpected error occurred in carbide api setup: {}", err);
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
        api_url: figment
            .extract_inner::<String>("carbide_api_url")
            .map_err(|_| "Could not extract carbide_api_url from config")?,
        pxe_url: figment
            .extract_inner::<String>("carbide_pxe_url")
            .map_err(|_| "Could not extract carbide_pxe_url from config")?,
        ntp_server: figment
            .extract_inner::<String>("carbide_ntp_server")
            .map_err(|_| "Could not extract ntp_server from config")?,
    })
}
