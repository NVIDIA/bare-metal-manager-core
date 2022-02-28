use std::convert::TryFrom;

use carbide::{
    db::{DhcpRecord, Machine, MachineIdsFilter, NetworkSegment, NewNetworkSegment, NewInstanceType},
    CarbideError,
};
use color_eyre::Report;
use mac_address::MacAddress;
use tonic::{Request, Response, Status};

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};

use self::rpc::metal_server::Metal;
use crate::cfg;
use rpc::v0 as rpc;
use tonic_reflection::server::Builder;

#[derive(Debug)]
pub struct Api {
    database_connection: sqlx::PgPool,
}

#[tonic::async_trait]
impl Metal for Api {
    async fn find_machines(
        &self,
        request: Request<rpc::MachineSearchQuery>,
    ) -> Result<Response<rpc::MachineList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::MachineSearchQuery { id, .. } = request.into_inner();

        let filter = match id {
            Some(id) if id.value.chars().count() > 0 => match uuid::Uuid::try_from(id) {
                Ok(uuid) => MachineIdsFilter::One(uuid),
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Supplied invalid UUID: {}",
                        err
                    )))
                }
            },
            _ => MachineIdsFilter::All,
        };

        Ok(Machine::find(&mut txn, filter)
            .await
            .map(|machine| rpc::MachineList {
                machines: machine.into_iter().map(rpc::Machine::from).collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?)
    }

    async fn discover_machine(
        &self,
        request: Request<rpc::MachineDiscovery>,
    ) -> Result<Response<rpc::DhcpRecord>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::MachineDiscovery {
            mac_address,
            relay_address,
            ..
        } = request.into_inner();

        let parsed_mac: MacAddress = mac_address
            .parse::<MacAddress>()
            .map_err(|e| CarbideError::GenericError(e.to_string()))?;

        Machine::discover(&mut txn, parsed_mac, relay_address.parse().unwrap()).await?;

        let network = NetworkSegment::for_relay(&mut txn, relay_address.parse().unwrap())
            .await?
            .unwrap();

        let response = Ok(Response::new(
            DhcpRecord::find_by_id_ipv4(&mut txn, &parsed_mac, network.id())
                .await?
                .into(),
        ));

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    async fn find_network_segments(
        &self,
        _request: Request<rpc::NetworkSegmentQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let network = NetworkSegment::find(&mut txn)
            .await
            .map(|network| rpc::NetworkSegmentList {
                network_segments: network.into_iter().map(rpc::NetworkSegment::from).collect(),
            })
            .map(rpc::NetworkSegmentList::from)
            .map(Response::new)
            .map_err(CarbideError::from)?;
        //.map_err(|e| Status::new(Code::Internal, format!("{:?}", e)));

        Ok(network)
    }

    async fn create_network_segment(
        &self,
        request: Request<rpc::NetworkSegment>,
    ) -> Result<Response<rpc::NetworkSegment>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(NewNetworkSegment::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map(rpc::NetworkSegment::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    async fn delete_network_segment(
        &self,
        _request: Request<rpc::NetworkSegmentDeletion>,
    ) -> Result<Response<rpc::NetworkSegmentDeletionResult>, Status> {
        let txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        // TODO(ajf): actually delete the thing, or likely return an error.

        let response = Ok(Response::new(rpc::NetworkSegmentDeletionResult {}));

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    async fn create_project(
        &self,
        _request: Request<rpc::Project>,
    ) -> Result<Response<rpc::Project>, Status> {
        todo!()
    }

    async fn update_project(
        &self,
        _request: Request<rpc::Project>,
    ) -> Result<Response<rpc::Project>, Status> {
        todo!()
    }

    async fn delete_project(
        &self,
        _request: Request<rpc::ProjectDeletion>,
    ) -> Result<Response<rpc::ProjectDeletionResult>, Status> {
        todo!()
    }

    async fn update_network_segment(
        &self,
        _request: Request<rpc::NetworkSegment>,
    ) -> Result<Response<rpc::NetworkSegment>, Status> {
        todo!()
    }

    async fn create_instance(
        &self,
        _request: Request<rpc::Instance>,
    ) -> Result<Response<rpc::Instance>, Status> {
        todo!()
    }

    async fn update_instance(
        &self,
        _request: Request<rpc::Instance>,
    ) -> Result<Response<rpc::Instance>, Status> {
        todo!()
    }

    async fn delete_instance(
        &self,
        _request: Request<rpc::InstanceDeletionRequest>,
    ) -> Result<Response<rpc::InstanceDeletionResult>, Status> {
        todo!()
    }

    async fn invoke_instance_power(
        &self,
        _request: Request<rpc::InstancePowerRequest>,
    ) -> Result<Response<rpc::InstancePowerResult>, Status> {
        todo!()
    }

    async fn get_machine(
        &self,
        _request: Request<rpc::Uuid>,
    ) -> Result<Response<rpc::Machine>, Status> {
        todo!()
    }

    async fn create_instance_type(
        &self,
        _request: Request<rpc::InstanceType>,
    ) -> Result<Response<rpc::InstanceType>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(NewInstanceType::try_from(_request.into_inner())?
            .persist(&mut txn)
            .await
            .map(rpc::InstanceType::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    async fn update_instance_type(
        &self,
        _request: Request<rpc::InstanceType>,
    ) -> Result<Response<rpc::InstanceType>, Status> {
        todo!()
    }

    async fn delete_instance_type(
        &self,
        _request: Request<rpc::InstanceTypeDeletion>,
    ) -> Result<Response<rpc::InstanceTypeDeletionResult>, Status> {
        todo!()
    }
}

impl Api {
    pub async fn run(daemon_config: &cfg::Daemon) -> Result<(), Report> {
        info!("Starting API server on {:?}", daemon_config.listen[0]);

        let database_connection = sqlx::Pool::connect(&daemon_config.datastore).await?;

        let api_service = Api {
            database_connection,
        };

        let reflection_service = Builder::configure()
            .register_encoded_file_descriptor_set(rpc::REFLECTION_SERVICE_DESCRIPTOR)
            .build()?;

        tonic::transport::Server::builder()
            //            .tls_config(ServerTlsConfig::new().identity( Identity::from_pem(&cert, &key) ))?
            .add_service(rpc::metal_server::MetalServer::new(api_service))
            .add_service(reflection_service)
            .serve(daemon_config.listen[0])
            .await?;

        Ok(())
    }
}
