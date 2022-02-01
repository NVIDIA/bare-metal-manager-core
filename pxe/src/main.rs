#[macro_use]
extern crate rocket;

use clap::Parser;

use serde::Serialize;
use std::{default::Default, fmt::Debug, fmt::Display};
use uuid::Uuid;

mod routes;

use rocket::{
    fairing::AdHoc,
    form::Errors,
    fs::{relative, FileServer},
    http::Status,
    request::{self, FromParam, FromRequest},
    Request,
};
use rocket_dyn_templates::Template;

use rpc::v0::{carbide_client::CarbideClient, MachineQuery};

#[derive(Debug)]
pub struct Machine(rpc::v0::Machine);

struct CarbideUrl(String);

pub enum RPCError<'a> {
    RequestError(tonic::Status),
    MissingClientConfig,
    MissingMachineId,
    MalformedMachineId(Errors<'a>),
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
        serializer.serialize_newtype_struct("Machine", &self.0)
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
            }
        )
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Machine {
    type Error = RPCError<'r>;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let uuid = match request.query_value::<Uuid>("uuid") {
            Some(Ok(uuid)) => uuid,
            Some(Err(errs)) => {
                return request::Outcome::Failure((
                    Status::BadRequest,
                    RPCError::MalformedMachineId(errs),
                ))
            }
            None => {
                eprintln!("{:#?}", request.param::<Uuid>(0));
                match request.param::<Uuid>(0) {
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

        let mut client = match request.rocket().state::<CarbideUrl>() {
            Some(url) => match CarbideClient::connect(url.0.clone()).await {
                Ok(client) => client,
                Err(err) => {
                    return request::Outcome::Failure((
                        Status::BadRequest,
                        RPCError::MissingClientConfig,
                    ))
                }
            },
            None => {
                return request::Outcome::Failure((
                    Status::BadRequest,
                    RPCError::MissingClientConfig,
                ))
            }
        };

        let request = tonic::Request::new(MachineQuery {
            id: Some(uuid.into()),
            ..Default::default()
        });

        match client.find_machines(request).await {
            Ok(response) => {
                request::Outcome::Success(Machine(response.into_inner().machines.remove(0)))
            }
            Err(err) => {
                request::Outcome::Failure((Status::BadRequest, RPCError::RequestError(err)))
            }
        }
    }
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let opts = Args::parse();

    rocket::build()
        .mount("/api/v0/pxe", routes::ipxe::routes())
        .mount("/api/v0/cloud-init", routes::cloud_init::routes())
        .mount("/public", FileServer::from(String::from(opts.static_dir)))
        .attach(Template::fairing())
        .attach(AdHoc::try_on_ignite(
            "Carbide API Config",
            |rocket| async move {
                match rocket.figment().extract_inner::<String>("carbide_api_url") {
                    Ok(url) => Ok(rocket.manage(CarbideUrl(url))),
                    Err(_) => Err(rocket),
                }
            },
        ))
        .ignite()
        .await?
        .launch()
        .await
}
