#[macro_use]
extern crate rocket;

use clap::Parser;

use serde::Serialize;
use std::{default::Default, fmt::Debug, fmt::Display};

mod routes;

use rocket::request::Outcome;
use rocket::{
    fairing::AdHoc,
    form::Errors,
    fs::FileServer,
    http::Status,
    request::{self, FromRequest},
    Request,
};
use rocket_dyn_templates::Template;

use rpc::forge::v0;

use ::rpc::forge::v0::forge_client::ForgeClient;
use ::rpc::forge::v0::InterfaceSearchQuery;

#[derive(Debug)]
pub struct Machine {
    #[allow(dead_code)]
    architecture: v0::MachineArchitecture,
    interface: v0::MachineInterface,
    machine: Option<v0::Machine>
}

#[derive(Clone)]
pub struct RuntimeConfig {
    api_url: String,
    pxe_url: String,
}

pub enum RPCError<'a> {
    RequestError(tonic::Status),
    MissingClientConfig,
    MissingMachineId,
    MissingBuildArch,
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
                RPCError::MissingBuildArch =>
                    "Missing Build arch specified in URI parameter buildarch".to_string(),
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
            Some(Ok(buildarch)) => { match buildarch {
                "arm64" => v0::MachineArchitecture::Arm,
                "x86_64" => v0::MachineArchitecture::X86,
                arch => {
                    eprintln!("invalid architecture: {:#?}", arch);
                    return request::Outcome::Failure((
                        Status::BadRequest,
                        RPCError::InvalidBuildArch,
                    ))
                }
            }},
            Some(Err(errs)) => {
                return request::Outcome::Failure((
                    Status::BadRequest,
                    RPCError::MalformedBuildArch(errs),
                ))
            },

            None => {
                eprintln!("{:#?}", request.param::<&str>(1));
                match request.param::<&str>(1) {
                    Some(buildarch) => { match buildarch.unwrap() {
                        "arm64" => { v0::MachineArchitecture::Arm }
                        arch => {
                            eprintln!("invalid architecture: {:#?}", arch);
                            return request::Outcome::Failure((
                                Status::BadRequest,
                                RPCError::InvalidBuildArch,
                            ))
                        }
                    }},
                    None => {
                        return request::Outcome::Failure((
                            Status::BadRequest,
                            RPCError::MissingBuildArch,
                        ))
                    }
                }
            }
        };
        let uuid = match request.query_value::<rocket::serde::uuid::Uuid>("uuid") {
            Some(Ok(uuid)) => uuid,
            Some(Err(errs)) => {
                return request::Outcome::Failure((
                    Status::BadRequest,
                    RPCError::MalformedMachineId(errs),
                ))
            }
            None => {
                eprintln!("{:#?}", request.param::<rocket::serde::uuid::Uuid>(0));
                match request.param::<rocket::serde::uuid::Uuid>(0) {
                    Some(uuid) => uuid.unwrap(),
                    None => {
                        return request::Outcome::Failure((
                            Status::BadRequest,
                            RPCError::MissingMachineId,
                        ))
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
            id: Some(rpc::forge::v0::Uuid {
                value: uuid.to_string(),
            }),
        });

        let interface = match client.find_interfaces(request).await {
            // TODO(baz): fix this blatantly ugly remove(0) w/o checking the size
            Ok(response) => response.into_inner().interfaces.remove(0),
            Err(err) => {
                return request::Outcome::Failure((Status::BadRequest, RPCError::RequestError(err)))
            }
        };

        match interface.machine_id.clone() {
            None => request::Outcome::Success(Machine {
                architecture: buildarch,
                interface,
                machine: None,
            }),
            Some(machine_id) => {
                let request = tonic::Request::new(machine_id);
                match client.get_machine(request).await {
                    Ok(machine) => request::Outcome::Success(Machine {
                        architecture: buildarch,
                        interface,
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
        info!(
            "Static path {} does not exist. Creating directory",
            &static_path.display()
        );

        match std::fs::create_dir_all(&static_path) {
            Ok(_) => info!("Directory {}, created", &static_path.display()),
            Err(e) => error!("Could not create directory: {}", e),
        }
    }

    rocket::build()
        .mount("/api/v0/pxe", routes::ipxe::routes())
        .mount("/api/v0/cloud-init", routes::cloud_init::routes())
        .mount("/public", FileServer::from(String::from(opts.static_dir)))
        .attach(Template::fairing())
        .attach(AdHoc::try_on_ignite(
            "Carbide API Config",
            |rocket| async move {
                if let Ok(api_url) = rocket.figment().extract_inner::<String>("carbide_api_url") {
                    if let Ok(pxe_url) = rocket.figment().extract_inner::<String>("carbide_pxe_url")
                    {
                        Ok(rocket.manage(RuntimeConfig { api_url, pxe_url }))
                    } else {
                        Err(rocket)
                    }
                } else {
                    Err(rocket)
                }
            },
        ))
        .ignite()
        .await?
        .launch()
        .await
}
