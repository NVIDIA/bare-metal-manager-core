use std::convert::TryFrom;

use carbide::{
    db::{DhcpRecord, Machine, MachineIdsFilter, NetworkSegment, NewNetworkSegment},
    CarbideError,
};
use color_eyre::Report;
use mac_address::MacAddress;
use tonic::{Request, Response, Status};

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};

use self::rpc::carbide_server::Carbide;
use crate::cfg;
use rpc::v0 as rpc;
use tonic_reflection::server::Builder;

#[derive(Debug)]
pub struct Api {
    database_connection: sqlx::PgPool,
}

#[tonic::async_trait]
impl Carbide for Api {
    async fn find_machines(
        &self,
        request: Request<rpc::MachineQuery>,
    ) -> Result<Response<rpc::MachineList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::MachineQuery { id, .. } = request.into_inner();

        let filter = match id {
            Some(id) => MachineIdsFilter::One(uuid::Uuid::try_from(id).unwrap()),
            None => MachineIdsFilter::All,
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

    async fn get_network_segments(
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
        request: Request<rpc::NewNetworkSegment>,
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
        _request: Request<rpc::Uuid>,
    ) -> Result<Response<rpc::NetworkSegmentDeletion>, Status> {
        let txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        //    carbide::models::NetworkSegment::find_by_id(&txn);

        let response = Ok(Response::new(rpc::NetworkSegmentDeletion {}));

        txn.commit().await.map_err(CarbideError::from)?;

        response
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
            .add_service(rpc::carbide_server::CarbideServer::new(api_service))
            .add_service(reflection_service)
            .serve(daemon_config.listen[0])
            .await?;

        Ok(())
    }
}
