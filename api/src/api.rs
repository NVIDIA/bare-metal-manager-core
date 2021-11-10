use color_eyre::Report;
use tonic::{Code, Request, Response, Status};

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};

use carbide::db::{Datastore, Machine, MachineIdsFilter, NetworkSegment, Pool};

use self::rpc::carbide_server::Carbide;
use ip_network::{IpNetworkParseError, Ipv4Network, Ipv6Network};
use rpc::v0 as rpc;

use crate::cfg;
use tonic_reflection::server::Builder;

//use tonic::transport::{ServerTlsConfig, Server, Identity};
// use hashicorp_vault::Client as VaultClient;
//use hashicorp_vault::client::EndpointResponse;

#[derive(Debug)]
pub struct Api {
    database_pool: Pool,
    #[allow(dead_code)]
    database_url: String, // Hack because bb8 and tokio-postgres wind up hiding the connection polling API
}

#[tonic::async_trait]
impl Carbide for Api {
    async fn find_machines(
        &self,
        request: Request<rpc::MachineQuery>,
    ) -> Result<Response<rpc::MachineList>, Status> {
        info!("Starting get_machines for request: {:?}", request);

        match self.database_pool.get().await {
            Ok(mut pool) => {
                info!("Retrieved connection from the database pool");
                match pool.transaction().await {
                    Ok(txn) => {
                        info!("Opened transaction");

                        let machines = Machine::find(&txn, MachineIdsFilter::All)
                            .await
                            .map(|machine| rpc::MachineList {
                                machines: machine.into_iter().map(rpc::Machine::from).collect(),
                            })
                            .map(Response::new)
                            .map_err(|e| Status::new(Code::Internal, format!("{:?}", e)));

                        info!("Machines: {:?}", machines);

                        machines
                    }
                    Err(e) => Err(Status::new(Code::Internal, e.to_string())),
                }
            }
            Err(e) => Err(Status::new(Code::Internal, e.to_string())),
        }
    }

    async fn discover_machine(
        &self,
        request: Request<rpc::MachineDiscovery>,
    ) -> Result<Response<rpc::Machine>, Status> {
        info!("Starting discover_machine for request: {:?}", request);

        match self.database_pool.get().await {
            Ok(mut pool) => {
                info!("Retrieved connection from the database pool");
                match pool.transaction().await {
                    Ok(mut txn) => {
                        info!("Opened transaction");

                        let rpc::MachineDiscovery {
                            mac_address,
                            relay_address,
                            ..
                        } = request.into_inner();

                        let machine = Machine::discover(
                            &mut txn,
                            mac_address.parse().unwrap(),
                            relay_address.parse().unwrap(),
                        )
                        .await
                        .map(rpc::Machine::from)
                        .map(Response::new)
                        .map_err(|e| Status::new(Code::Internal, format!("{}", e)));

                        info!("Machine = {:?}", machine);

                        txn.commit()
                            .await
                            .map_err(|e| Status::new(Code::Internal, format!("{}", e)))?;

                        machine
                    }
                    Err(e) => Err(Status::new(Code::Internal, e.to_string())),
                }
            }
            Err(e) => Err(Status::new(Code::Internal, e.to_string())),
        }
    }

    async fn get_network_segments(
        &self,
        _request: Request<rpc::NetworkSegmentQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        match self.database_pool.get().await {
            Ok(mut pool) => {
                info!("Retrieved connection from the database pool");
                match pool.transaction().await {
                    Ok(txn) => {
                        info!("Opened transaction");

                        let network = NetworkSegment::find(&txn)
                            .await
                            .map(|network| rpc::NetworkSegmentList {
                                network_segments: network
                                    .into_iter()
                                    .map(rpc::NetworkSegment::from)
                                    .collect(),
                            })
                            .map(rpc::NetworkSegmentList::from)
                            .map(Response::new)
                            .map_err(|e| Status::new(Code::Internal, format!("{:?}", e)));

                        info!("Network = {:?}", network);

                        network
                    }
                    Err(e) => Err(Status::new(Code::Internal, e.to_string())),
                }
            }
            Err(e) => Err(Status::new(Code::Internal, e.to_string())),
        }
    }

    async fn create_network_segment(
        &self,
        request: Request<rpc::NetworkSegment>,
    ) -> Result<Response<rpc::NetworkSegment>, Status> {
        match self.database_pool.get().await {
            Ok(mut pool) => {
                info!("Retrieved connection from the database pool");
                match pool.transaction().await {
                    Ok(txn) => {
                        info!("Opened transaction");

                        let rpc::NetworkSegment {
                            id: _,
                            name,
                            subdomain,
                            mtu,
                            subnet_ipv4: maybe_subnet_ipv4,
                            subnet_ipv6: maybe_subnet_ipv6,
                            reserve_first_ipv4,
                            reserve_first_ipv6,
                        } = request.into_inner();

                        let subnet_ipv4: Option<Result<Ipv4Network, Status>> = maybe_subnet_ipv4
                            .map(|ip| {
                                ip.parse().map_err(|e: IpNetworkParseError| {
                                    Status::new(
                                        Code::InvalidArgument,
                                        format!(
                                            "Unable to parse IPv4 network subnet: {0}",
                                            e.to_string()
                                        ),
                                    )
                                })
                            });

                        if let Some(Err(parse_error)) = subnet_ipv4 {
                            return Err(parse_error);
                        }

                        let subnet_ipv6: Option<Result<Ipv6Network, Status>> = maybe_subnet_ipv6
                            .map(|ip| {
                                ip.parse().map_err(|e: IpNetworkParseError| {
                                    Status::new(
                                        Code::InvalidArgument,
                                        format!(
                                            "Unable to parse IPv6 network subnet: {0}",
                                            e.to_string()
                                        ),
                                    )
                                })
                            });

                        if let Some(Err(parse_error)) = subnet_ipv6 {
                            return Err(parse_error);
                        }

                        let segment = NetworkSegment::create(
                            &txn,
                            &name,
                            &subdomain,
                            &mtu,
                            subnet_ipv4.map(|result| result.unwrap()),
                            subnet_ipv6.map(|result| result.unwrap()),
                            &reserve_first_ipv4,
                            &reserve_first_ipv6,
                        )
                        .await
                        .map(rpc::NetworkSegment::from)
                        .map(Response::new)
                        .map_err(|e| Status::new(Code::Internal, format!("{:?}", e)));

                        info!("NetworkSegment = {:?}", segment);

                        txn.commit().await.unwrap();

                        segment
                    }
                    Err(e) => Err(Status::new(Code::Internal, e.to_string())),
                }
            }
            Err(e) => Err(Status::new(Code::Internal, e.to_string())),
        }
    }
    async fn delete_network_segment(
        &self,
        _request: Request<rpc::Uuid>,
    ) -> Result<Response<rpc::NetworkSegmentDeletion>, Status> {
        match self.database_pool.get().await {
            Ok(mut pool) => {
                info!("Retrieved connection from the database pool");
                match pool.transaction().await {
                    Ok(_txn) => {
                        info!("Opened transaction");

                        //    carbide::models::NetworkSegment::find_by_id(&txn);

                        Ok(Response::new(rpc::NetworkSegmentDeletion {}))
                    }
                    Err(e) => Err(Status::new(Code::Internal, e.to_string())),
                }
            }
            Err(e) => Err(Status::new(Code::Internal, e.to_string())),
        }
    }

    //    type EventsStream = ReceiverStream<Result<rpc::EventMessage, Status>>;
    //
    //    async fn events(
    //        &self,
    //        request: Request<rpc::EventRequest>,
    //    ) -> Result<Response<Self::EventsStream>, Status> {
    //        info!("Got a request: {:?}", request);
    //
    //        let (client, connection) =
    //            match carbide::Datastore::direct_from_url(&self.database_url[..]).await {
    //                Ok(v) => v,
    //                Err(error) => return Err(Status::new(Code::Internal, error.to_string())),
    //            };
    //
    //        let (tx, rx) = mpsc::unbounded();
    //
    //        let stream =
    //            stream::poll_fn(move |cx| connection.poll_message(cx)).map_err(|e| panic!("{:?}", e));
    //
    //        let connection = stream.forward(tx).map(|r| r.unwrap());
    //
    //        tokio::spawn(connection);
    //
    //        let notifications = rx.filter_map(|m| match m {
    //            AsyncMessage::Notification(n) => future::ready(Some(n)),
    //            _ => future::ready(Node),
    //        });
    //
    //        //        tokio::spawn(async move {
    //        //            for number in numbers {
    //        //                let out_message = rpc::EventMessage {
    //        //                    emitted: Some(SystemTime::now().into()),
    //        //                    event: Some(rpc::event_message::Event::MachineAdded(
    //        //                        rpc::EventMachineAdded {
    //        //                            id: Some(rpc::Uuid {
    //        //                                value: number.to_string(),
    //        //                            }),
    //        //                        },
    //        //                    )),
    //        //                };
    //        //
    //        //                tx.send(Ok(out_message)).await.unwrap();
    //        //            }
    //        //        });
    //        //
    //        Ok(Response::new(ReceiverStream::new(rx)))
    //    }
}

impl Api {
    pub fn new(datastore: Pool, database_url: &str) -> Self {
        Self {
            database_pool: datastore,
            database_url: String::from(database_url),
        }
    }

    pub async fn run(daemon_config: &cfg::Daemon) -> Result<(), Report> {
        info!("Starting API server on {:?}", daemon_config.listen[0]);

        let api_service = Api::new(
            Datastore::pool_from_url(&daemon_config.datastore).await?,
            &daemon_config.datastore,
        );

        let reflection_service = Builder::configure()
            .register_encoded_file_descriptor_set(rpc::REFLECTION_SERVICE_DESCRIPTOR)
            .build()?;

        //       let _vault_client = VaultClient::new(
        //           &daemon_config.vault_api,
        //           &daemon_config.vault_token,
        //       )?;
        //
        //        let response: EndpointResponse<String> = vault_client.call_endpoint(
        //            hashicorp_vault::client::HttpVerb::PUT,
        //            "pki/issue/carbide-api-server",
        //            None,
        //            Some("{\"name\": \"carbide-api.example.com\", \"common_name\": \"carbide-api.example.com\" }"))?;
        //
        //        info!("{:#?}", response);

        tonic::transport::Server::builder()
            //            .tls_config(ServerTlsConfig::new().identity( Identity::from_pem(&cert, &key) ))?
            .add_service(rpc::carbide_server::CarbideServer::new(api_service))
            .add_service(reflection_service)
            .serve(daemon_config.listen[0])
            .await?;

        Ok(())
    }
}
