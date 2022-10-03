use std::convert::TryFrom;
use std::env;
use std::sync::RwLock;

use color_eyre::Report;
use lru::LruCache;
use mac_address::MacAddress;
use once_cell::sync::Lazy;
use sqlx::Acquire;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tonic_reflection::server::Builder;
use tower::ServiceBuilder;

pub use ::rpc::forge as rpc;
use ::rpc::MachineStateMachineInput;
use auth::CarbideAuth;
use carbide::db::instance::Instance;
use carbide::db::instance_subnet::InstanceSubnet;
use carbide::db::network_prefix::NetworkPrefix;
use carbide::ipmi::{ipmi_handler, RealIpmiCommandHandler};
use carbide::kubernetes::{
    bgkubernetes_handler, create_managed_resource, create_resource_group, delete_managed_resource,
    delete_resource_group,
};
use carbide::{
    db::{
        auth::SshKeyValidationRequest,
        domain::Domain,
        domain::NewDomain,
        instance::{DeleteInstance, NewInstance},
        instance_type::{DeactivateInstanceType, NewInstanceType, UpdateInstanceType},
        ipmi::{BmcMetaData, BmcMetaDataRequest},
        machine::Machine,
        machine_interface::MachineInterface,
        machine_state::MachineState,
        machine_topology::MachineTopology,
        network_segment::{NetworkSegment, NewNetworkSegment},
        resource_record::DnsQuestion,
        tags::{Tag, TagAssociation, TagCreate, TagDelete, TagsList},
        vpc::{DeleteVpc, NewVpc, UpdateVpc, Vpc},
        UuidKeyedObjectFilter,
    },
    CarbideError,
};

use crate::auth;
use crate::cfg;
use crate::dhcp_discover::RecordCacheEntry;

use self::rpc::forge_server::Forge;

pub struct ExternalConfig {
    pub dhcp_server: Option<String>,
}
pub static CONFIG: Lazy<RwLock<ExternalConfig>> =
    Lazy::new(|| RwLock::new(ExternalConfig { dhcp_server: None }));

#[derive(Debug)]
pub struct Api {
    pub(crate) database_connection: sqlx::PgPool,
    pub(crate) dhcp_discovery_cache: Mutex<LruCache<MacAddress, RecordCacheEntry>>,
}

#[tonic::async_trait]
impl Forge for Api {
    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
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
                query_name: Some(q_name),
                query_type: q_type,
                query_class: q_class,
            },
            None => {
                return Err(Status::invalid_argument(
                    "A valid q_name, q_type and q_class are required",
                ));
            }
        };

        let results = DnsQuestion::find_record(&mut txn, question)
            .await
            .map(|dnsrr| rpc::dns_message::DnsResponse {
                rcode: dnsrr.response_code,
                rrs: dnsrr
                    .resource_records
                    .into_iter()
                    .map(|r| r.into())
                    .collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(results)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
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

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_vpcs(
        &self,
        request: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<rpc::VpcList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::VpcSearchQuery { id, name, .. } = request.into_inner();

        let vpcs = match (id, name) {
            (Some(id), _ ) => {
                let id = id;
                let uuid = match uuid::Uuid::try_from(id) {
                    Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                    Err(err) => {
                        return Err(Status::invalid_argument(format!(
                            "Supplied invalid UUID: {}",
                            err
                        )));
                    }
                };
                Vpc::find(&mut txn, uuid)
                    .await
            },
            (None, Some(name)) => {
                Vpc::find_by_name(&mut txn, name)
                    .await
            },
            (None, None) => {
                Vpc::find(&mut txn, UuidKeyedObjectFilter::All)
                    .await
            },
        };

        let result = vpcs
            .map(|vpc |rpc::VpcList {
                vpcs: vpc.into_iter().map(rpc::Vpc::from).collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(result)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_interfaces(
        &self,
        request: Request<rpc::InterfaceSearchQuery>,
    ) -> Result<Response<rpc::InterfaceList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::InterfaceSearchQuery { id, .. } = request.into_inner();

        let response = match id {
            Some(id) if id.value.chars().count() > 0 => match uuid::Uuid::try_from(id) {
                Ok(uuid) => Ok(rpc::InterfaceList {
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

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
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

        let result = Machine::find(&mut txn, _uuid)
            .await
            .map(|m| rpc::MachineList {
                machines: m.into_iter().map(rpc::Machine::from).collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(result)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn discover_dhcp(
        &self,
        request: Request<rpc::DhcpDiscovery>,
    ) -> Result<Response<rpc::DhcpRecord>, Status> {
        crate::dhcp_discover::discover_dhcp(self, request).await
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn done(&self, request: Request<rpc::Uuid>) -> Result<Response<rpc::Machine>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let uuid = uuid::Uuid::try_from(request.into_inner()).map_err(CarbideError::from)?;

        let interface = MachineInterface::find_one(&mut txn, uuid).await?;

        let maybe_machine = match interface.machine_id {
            Some(machine_id) => Machine::find_one(&mut txn, machine_id).await?,
            None => {
                return Err(Status::invalid_argument(format!(
                    "Machine interface has no machine id UUID: {}",
                    uuid
                )));
            }
        };

        let response = match maybe_machine {
            None => Err(CarbideError::NotFoundError(uuid).into()),
            Some(machine) => Ok(rpc::Machine::from(machine)),
        }
        .map(Response::new);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn discover_machine(
        &self,
        request: Request<rpc::MachineDiscoveryInfo>,
    ) -> Result<Response<rpc::MachineDiscoveryResult>, Status> {
        let di = request.into_inner();

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let interface_id = match &di.machine_id {
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

        MachineTopology::create(&mut txn, &uuid, &di).await?;

        let response = Ok(Response::new(rpc::MachineDiscoveryResult {}));

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_network_segments(
        &self,
        request: Request<rpc::NetworkSegmentQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        log::debug!("Fetching database transaction");

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::NetworkSegmentQuery{ id, .. } = request.into_inner();

        let uuid_filter = match id {
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

        let result = NetworkSegment::find(&mut txn, uuid_filter)
            .await
            .map(|network| rpc::NetworkSegmentList {
                network_segments: network.into_iter().map(rpc::NetworkSegment::from).collect(),
            })
            .map(rpc::NetworkSegmentList::from)
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(result)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn create_network_segment(
        &self,
        request: Request<rpc::NetworkSegment>,
    ) -> Result<Response<rpc::NetworkSegment>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = NewNetworkSegment::try_from(request.into_inner())?
            .persist(&mut txn)
            .await;

        let dhcp_server = CONFIG.read().unwrap().dhcp_server.clone();
        let db_conn = txn.acquire().await.map_err(CarbideError::from)?;

        if let Ok(segment) = response.as_ref() {
            for prefix in &segment.prefixes {
                create_resource_group(prefix, db_conn, dhcp_server.clone()).await?;
            }
        }

        let response = Ok(response.map(rpc::NetworkSegment::from).map(Response::new)?);
        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn delete_network_segment(
        &self,
        request: Request<rpc::NetworkSegmentDeletion>,
    ) -> Result<Response<rpc::NetworkSegmentDeletionResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::NetworkSegmentDeletion { id, .. } = request.into_inner();

        let uuid = match id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Supplied invalid UUID: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Status::invalid_argument("No UUID provided".to_string()));
            }
        };

        let mut segments = NetworkSegment::find(&mut txn, uuid).await?;

        let segment = match segments.len() {
            1 => segments.remove(0),
            _ => return Err(Status::not_found("network segment not found")),
        };

        // NOTE(jdg): We don't have to enforce the NULL subdomain and VPC entry here because
        // we're leaving that up to the object call and checking in the db layer instead

        let prefixes =
            NetworkPrefix::find_by_segment(&mut txn, UuidKeyedObjectFilter::One(*segment.id()))
                .await?;

        let response = Ok(segment
            .delete(&mut txn)
            .await
            .map(|_| rpc::NetworkSegmentDeletionResult {})
            .map(Response::new)?);

        let db_conn = txn.acquire().await.map_err(CarbideError::from)?;

        for prefix in &prefixes {
            delete_resource_group(prefix, db_conn).await?;
        }

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
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

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_domain(
        &self,
        request: Request<rpc::DomainSearchQuery>,
    ) -> Result<Response<rpc::DomainList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::DomainSearchQuery { id, .. } = request.into_inner();

        let uuid = match id {
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

        let result = Domain::find(&mut txn, uuid)
            .await
            .map(|domain| rpc::DomainList {
                domains: domain.into_iter().map(rpc::Domain::from).collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(result)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn update_domain(
        &self,
        request: Request<rpc::Domain>,
    ) -> Result<Response<rpc::Domain>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::Domain { id, name, .. } = request.into_inner();

        // TODO(jdg): Move this out into a function and share it with delete
        let uuid = match id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Supplied invalid UUID: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Status::not_found(
                    "No domain object found matching requested UUID".to_string(),
                ));
            }
        };

        let mut domains = Domain::find(&mut txn, uuid).await?;

        let mut dom = match domains.len() {
            0 => return Err(Status::not_found("domain not found")),
            1 => domains.remove(0),
            _ => {
                return Err(Status::internal(
                    "Found more than one domain with the specified UUID",
                ))
            }
        };

        dom.name = name;
        let response = Ok(dom
            .update(&mut txn)
            .await
            .map(rpc::Domain::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn delete_domain(
        &self,
        request: Request<rpc::DomainDeletion>,
    ) -> Result<Response<rpc::DomainDeletionResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::DomainDeletion { id, .. } = request.into_inner();

        // load from find from domain.rs
        let uuid = match id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Supplied invalid UUID: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Status::invalid_argument("No UUID provided".to_string()));
            }
        };

        let mut domains = Domain::find(&mut txn, uuid).await?;

        let dom = match domains.len() {
            0 => return Err(Status::not_found("domain not found")),
            1 => domains.remove(0),
            _ => {
                return Err(Status::internal(
                    "Found more than one domain with the specified UUID",
                ))
            }
        };

        let response = Ok(dom
            .delete(&mut txn)
            .await
            .map(|_| rpc::DomainDeletionResult {})
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
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

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
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

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
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

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn update_network_segment(
        &self,
        _request: Request<rpc::NetworkSegment>,
    ) -> Result<Response<rpc::NetworkSegment>, Status> {
        todo!()
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn create_instance(
        &self,
        request: Request<rpc::Instance>,
    ) -> Result<Response<rpc::Instance>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let instance = NewInstance::try_from(request.into_inner())?;
        let machine_id = &instance.machine_id.clone();
        // check the state of the machine
        let machine = match Machine::find_one(&mut txn, *machine_id).await? {
            None => {
                return Err(Status::invalid_argument(format!(
                    "Supplied invalid UUID: {}",
                    machine_id
                )));
            }
            Some(m) => m,
        };

        // A new instance can be created only in Ready state.
        match machine.current_state(&mut txn).await? {
            MachineState::Ready => {
                // Blindly march forward to ready
                machine
                    .advance(&mut txn, &MachineStateMachineInput::Assign)
                    .await?;
            }
            rest => {
                return Err(Status::invalid_argument(format!(
                    "Could not create instance given machine state {:?}",
                    rest
                )));
            }
        }

        let response = instance.persist(&mut txn).await;

        if let Ok(instance_details) = response.as_ref() {
            let machine_interface = MachineInterface::get_machine_interface_primary(
                instance_details.machine_id,
                &mut txn,
            )
            .await?;

            let subnet = InstanceSubnet::create(
                &mut txn,
                &machine_interface,
                instance.segment_id,
                *instance_details.id(),
                None,
            )
            .await?;

            let ip_addr = instance_details
                .assign_address(&mut txn, subnet, instance.segment_id)
                .await?;

            create_managed_resource(
                &mut txn,
                instance.segment_id,
                Some(machine_interface.mac_address),
                instance_details.managed_resource_id.to_string(),
                Some(ip_addr.to_string()),
            )
            .await?;
        }

        let response = Ok(response.map(rpc::Instance::from).map(Response::new)?);

        // TODO(baz): reboot the machine

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn update_instance(
        &self,
        _request: Request<rpc::Instance>,
    ) -> Result<Response<rpc::Instance>, Status> {
        todo!()
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn delete_instance(
        &self,
        request: Request<rpc::InstanceDeletionRequest>,
    ) -> Result<Response<rpc::InstanceDeletionResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let delete_instance = DeleteInstance::try_from(request.into_inner())?;
        let instance = delete_instance.delete(&mut txn).await?;

        // Change state to Decommissioned
        let machine = match Machine::find_one(&mut txn, instance.machine_id).await? {
            None => {
                return Err(Status::invalid_argument(format!(
                    "Supplied invalid UUID: {}",
                    instance.machine_id
                )));
            }
            Some(m) => m,
        };

        // After deleted instance, machine should be moved to Decommissioned state.
        match machine.current_state(&mut txn).await? {
            MachineState::Assigned => {
                machine
                    .advance(&mut txn, &MachineStateMachineInput::Unassign)
                    .await?;
            }
            rest => {
                return Err(Status::invalid_argument(format!(
                    "Could not create instance given machine state {:?}",
                    rest
                )));
            }
        };

        delete_managed_resource(&mut txn, instance.managed_resource_id.to_string()).await?;
        txn.commit().await.map_err(CarbideError::from)?;

        // TODO: Reboot machine

        Ok(Response::new(rpc::InstanceDeletionResult {}))
    }

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn invoke_instance_power(
        &self,
        _request: Request<rpc::InstancePowerRequest>,
    ) -> Result<Response<rpc::InstancePowerResult>, Status> {
        todo!()
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn get_machine(
        &self,
        request: Request<rpc::Uuid>,
    ) -> Result<Response<rpc::Machine>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let uuid = uuid::Uuid::try_from(request.into_inner()).map_err(CarbideError::from)?;

        let response = match Machine::find_one(&mut txn, uuid).await? {
            None => Err(CarbideError::NotFoundError(uuid).into()),
            Some(machine) => Ok(rpc::Machine::from(machine)),
        }
        .map(Response::new);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
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

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
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

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
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

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_instance_by_machine_id(
        &self,
        request: Request<rpc::Uuid>,
    ) -> Result<Response<rpc::Instance>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let uuid = uuid::Uuid::try_from(request.into_inner()).map_err(CarbideError::from)?;

        let response = Instance::find_by_machine_id(&mut txn, uuid)
            .await
            .map(rpc::Instance::from)
            .map(Response::new)?;

        txn.commit().await.map_err(CarbideError::from)?;

        Ok(response)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn create_tag(
        &self,
        request: Request<rpc::TagCreate>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(TagCreate::try_from(request.into_inner())?
            .create(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn delete_tag(
        &self,
        request: Request<rpc::TagDelete>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(TagDelete::try_from(request.into_inner())?
            .delete(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn set_tags(
        &self,
        request: Request<rpc::TagsList>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(TagsList::try_from(request.into_inner())?
            .assign(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn list_tags(
        &self,
        _request: Request<rpc::TagVoid>,
    ) -> Result<Response<rpc::TagsListResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(Tag::list_all(&mut txn).await.map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn assign_tag(
        &self,
        request: Request<rpc::TagAssign>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(TagAssociation::try_from(request.into_inner())?
            .assign(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn remove_tag(
        &self,
        request: Request<rpc::TagRemove>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(TagAssociation::try_from(request.into_inner())?
            .remove(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn validate_user_ssh_key(
        &self,
        request: Request<rpc::SshKeyValidationRequest>,
    ) -> Result<Response<rpc::SshKeyValidationResponse>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(SshKeyValidationRequest::try_from(request.into_inner())?
            .verify_user(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn get_bmc_meta_data(
        &self,
        request: Request<rpc::BmcMetaDataRequest>,
    ) -> Result<Response<rpc::BmcMetaDataResponse>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(BmcMetaDataRequest::try_from(request.into_inner())?
            .get_bmc_meta_data(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn update_bmc_meta_data(
        &self,
        request: Request<rpc::BmcMetaData>,
    ) -> Result<Response<rpc::BmcStatus>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(BmcMetaData::try_from(request.into_inner())?
            .update_bmc_meta_data(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }
}

fn update_external_config() {
    let dhcp_server =
        env::var("CARBIDE_DHCP_SERVER").expect("Env variable CARBIDE_DHCP_SERVER is not defined.");
    CONFIG.write().unwrap().dhcp_server = Some(dhcp_server);
}

impl Api {
    #[tracing::instrument(skip_all)]
    pub async fn run(daemon_config: &cfg::Daemon) -> Result<(), Report> {
        log::info!("Starting API server on {:?}", daemon_config.listen[0]);

        let database_connection = sqlx::Pool::connect(&daemon_config.datastore).await?;
        let conn_clone = database_connection.clone();
        let api_service = Api {
            database_connection,
            dhcp_discovery_cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(1000).unwrap(),
            )),
        };

        let mut authenticator = CarbideAuth::new();

        // FIXME: Don't ship with this enabled. Should it be a config option?
        authenticator.set_permissive_mode(true);

        // Example code just to show usage. Do not actually use this!
        /*
        authenticator.add_jwt_key(
            auth::Algorithm::RS256,
            auth::KeySpec::KeyID(String::from("wow this is a great key ID!")),
            auth::DecodingKey::from_base64_secret("dWggb2g=").unwrap(),
        );
        */

        update_external_config();

        let auth_layer = ServiceBuilder::new()
            .layer(tower_http::auth::RequireAuthorizationLayer::custom(
                authenticator,
            ))
            .into_inner();

        let reflection_service = Builder::configure()
            .register_encoded_file_descriptor_set(::rpc::REFLECTION_SERVICE_DESCRIPTOR)
            .build()?;

        // handle should be stored in a variable. If is is dropped by compiler, main event will be dropped.
        let _handle = ipmi_handler(conn_clone, RealIpmiCommandHandler {}).await?;

        let _kube_handle =
            bgkubernetes_handler(daemon_config.datastore.to_owned(), daemon_config.kubernetes)
                .await?;

        tonic::transport::Server::builder()
            //            .tls_config(ServerTlsConfig::new().identity( Identity::from_pem(&cert, &key) ))?
            .layer(auth_layer)
            .add_service(rpc::forge_server::ForgeServer::new(api_service))
            .add_service(reflection_service)
            .serve(daemon_config.listen[0])
            .await?;

        Ok(())
    }
}
