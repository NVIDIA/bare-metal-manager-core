use std::convert::{TryFrom, TryInto};

use color_eyre::Report;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use mac_address::MacAddress;
use tonic::{Request, Response, Status};
use tonic_reflection::server::Builder;

use carbide::{
    db::{
        DeactivateInstanceType, DeleteVpc, DhcpRecord, DnsQuestion, Machine, MachineInterface,
        MachineTopology, NetworkSegment, NewDomain, NewInstanceType, NewNetworkSegment, NewVpc,
        UpdateInstanceType, UpdateVpc, UuidKeyedObjectFilter, Vpc,
    },
    CarbideError,
};
use rpc::v0 as rpc;

use crate::cfg;

use self::rpc::metal_server::Metal;

#[derive(Debug)]
pub struct Api {
    database_connection: sqlx::PgPool,
}

#[tonic::async_trait]
impl Metal for Api {
    async fn lookup_record(
        &self,
        request: Request<rpc::dns_message::DnsQuestion>,
    ) -> Result<Response<rpc::dns_message::DnsResponse>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::dns_message::DnsQuestion {
            q_name,
            q_type,
            q_class,
        } = request.into_inner();

        let question = match q_name.clone() {
            Some(q_name) => DnsQuestion {
                q_name: Some(q_name),
                q_type,
                q_class,
            },
            None => {
                return Err(Status::invalid_argument(
                    "A valid q_name, q_type and q_class are required",
                ))
            }
        };

        let results = DnsQuestion::find_record(&mut txn, question)
            .await
            .map(|dnsrr| rpc::dns_message::DnsResponse {
                rcode: dnsrr.rcode,
                rrs: dnsrr.rrs.into_iter().map(|r| r.into()).collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(results)
    }

    async fn network_segments_for_vpc(
        &self,
        request: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::VpcSearchQuery { id, .. } = request.into_inner();

        let _uuid = match id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => uuid,
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Did not supply a valid VPC_ID UUID: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Status::invalid_argument("A VPC_ID UUID is required"));
            }
        };

        let results = NetworkSegment::for_vpc(&mut txn, _uuid)
            .await
            .map(|network_segment| rpc::NetworkSegmentList {
                network_segments: network_segment
                    .into_iter()
                    .map(rpc::NetworkSegment::from)
                    .collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(results)
    }

    async fn find_vpcs(
        &self,
        request: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<rpc::VpcList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::VpcSearchQuery { id, .. } = request.into_inner();

        let _uuid = match id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Supplied invalid UUID: {}",
                        err
                    )));
                }
            },
            None => UuidKeyedObjectFilter::All,
        };

        let result = Vpc::find(&mut txn, _uuid)
            .await
            .map(|vpc| rpc::VpcList {
                vpcs: vpc.into_iter().map(rpc::Vpc::from).collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(result)
    }

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

        let response = match id {
            Some(id) if id.value.chars().count() > 0 => match uuid::Uuid::try_from(id) {
                Ok(uuid) => Ok(rpc::MachineList {
                    interfaces: vec![MachineInterface::find_one(&mut txn, uuid).await?.into()],
                }),
                Err(_) => Err(CarbideError::GenericError(
                    "Could not marshall an ID from the request".to_string(),
                )
                .into()),
            },
            _ => Err(
                CarbideError::GenericError("Could not find an ID in the request".to_string())
                    .into(),
            ),
        };

        response.map(Response::new)
    }

    async fn discover_dhcp(
        &self,
        request: Request<rpc::DhcpDiscovery>,
    ) -> Result<Response<rpc::DhcpRecord>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::DhcpDiscovery {
            mac_address,
            relay_address,
            ..
        } = request.into_inner();

        let parsed_mac: MacAddress = mac_address
            .parse::<MacAddress>()
            .map_err(|e| CarbideError::GenericError(e.to_string()))?;

        let parsed_relay = relay_address.parse().unwrap();

        let existing_machines =
            Machine::find_existing_machines(&mut txn, parsed_mac, parsed_relay).await?;

        match &existing_machines.len() {
            0 => {
                info!("No existing machine with mac address {} using network with relay: {}, creating one.", parsed_mac, parsed_relay);
                MachineInterface::validate_existing_mac_and_create(
                    &mut txn,
                    parsed_mac,
                    parsed_relay,
                )
                .await
            }
            1 => {
                let mut ifcs = MachineInterface::find_by_mac_address(&mut txn, parsed_mac).await?;
                match ifcs.len() {
                    1 => Ok(ifcs.remove(0)),
                    n => {
                        warn!(
                            "{0} existing mac address ({1}) for network segment (relay ip: {2})",
                            n, &mac_address, &relay_address
                        );
                        Err(CarbideError::NetworkSegmentDuplicateMacAddress(parsed_mac))
                    }
                }
            }
            _ => {
                warn!(
                    "More than machine found with mac address ({0}) for network segment (relay ip: {1})",
                    &mac_address, &relay_address
                );
                Err(CarbideError::NetworkSegmentDuplicateMacAddress(parsed_mac))
            }
        }?;

        txn.commit().await.map_err(CarbideError::from)?;

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        // There is some small bit of duplicated logic in the existing machines lookup and this.
        // A lookup for the machine interface is done above and could be combined with this if there
        // is a speed issue to overcome.
        let response = match NetworkSegment::for_relay(&mut txn, parsed_relay).await? {
            None => Err(CarbideError::NoNetworkSegmentsForRelay(parsed_relay).into()),
            Some(network) => Ok(Response::new(
                DhcpRecord::find_by_mac_address(&mut txn, &parsed_mac, network.id())
                    .await?
                    .into(),
            )),
        };

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    async fn discover_machine(
        &self,
        request: Request<rpc::MachineDiscovery>,
    ) -> Result<Response<rpc::MachineDiscoveryResult>, Status> {
        let di = request.into_inner();

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let interface_id = match &di.uuid {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => uuid,
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Did not supply a valid discovery machine id UUID: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Status::invalid_argument("An interface UUID is required"));
            }
        };

        let interface = MachineInterface::find_one(&mut txn, interface_id).await?;

        let json =
            serde_json::to_string(&di).map_err(|e| CarbideError::GenericError(e.to_string()))?;

        let machine = Machine::create(&mut txn, interface)
            .await
            .map(rpc::Machine::from)?;

        let uuid = match &machine.id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => uuid,
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Created machine did not return an proper UUID : {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Status::invalid_argument(
                    "No ID was associated with the machine",
                ));
            }
        };

        MachineTopology::create(&mut txn, &uuid, json).await?;

        let response = Ok(Response::new(rpc::MachineDiscoveryResult {}));

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

        let network = NetworkSegment::find(&mut txn, UuidKeyedObjectFilter::All)
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

    async fn create_domain(
        &self,
        request: Request<rpc::Domain>,
    ) -> Result<Response<rpc::Domain>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(NewDomain::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map(rpc::Domain::from)
            .map(Response::new)?);
        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    async fn update_domain(
        &self,
        _request: Request<rpc::Domain>,
    ) -> Result<Response<rpc::Domain>, Status> {
        todo!()
    }

    async fn delete_domain(
        &self,
        _request: Request<rpc::DomainDeletion>,
    ) -> Result<Response<rpc::DomainDeletionResult>, Status> {
        todo!()
    }

    async fn create_vpc(&self, request: Request<rpc::Vpc>) -> Result<Response<rpc::Vpc>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(NewVpc::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map(rpc::Vpc::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    async fn update_vpc(&self, request: Request<rpc::Vpc>) -> Result<Response<rpc::Vpc>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(UpdateVpc::try_from(request.into_inner())?
            .update(&mut txn)
            .await
            .map(rpc::Vpc::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    async fn delete_vpc(
        &self,
        request: Request<rpc::VpcDeletion>,
    ) -> Result<Response<rpc::VpcDeletionResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(DeleteVpc::try_from(request.into_inner())?
            .delete(&mut txn)
            .await
            .map(rpc::VpcDeletionResult::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
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
        request: Request<rpc::InstanceType>,
    ) -> Result<Response<rpc::InstanceType>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(NewInstanceType::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map(rpc::InstanceType::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    async fn update_instance_type(
        &self,
        request: Request<rpc::InstanceType>,
    ) -> Result<Response<rpc::InstanceType>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(UpdateInstanceType::try_from(request.into_inner())?
            .update(&mut txn)
            .await
            .map(rpc::InstanceType::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    async fn delete_instance_type(
        &self,
        request: Request<rpc::InstanceTypeDeletion>,
    ) -> Result<Response<rpc::InstanceTypeDeletionResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(DeactivateInstanceType::try_from(request.into_inner())?
            .deactivate(&mut txn)
            .await
            .map(rpc::InstanceTypeDeletionResult::from)
            .map(Response::new)?);

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
            .add_service(rpc::metal_server::MetalServer::new(api_service))
            .add_service(reflection_service)
            .serve(daemon_config.listen[0])
            .await?;

        Ok(())
    }
}
