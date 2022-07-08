#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DnsMessage {
    #[prost(message, optional, tag = "1")]
    pub question: ::core::option::Option<dns_message::DnsQuestion>,
    #[prost(message, optional, tag = "2")]
    pub response: ::core::option::Option<dns_message::DnsResponse>,
}
/// Nested message and enum types in `DNSMessage`.
pub mod dns_message {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DnsQuestion {
        /// FQDN including trailing dot
        #[prost(string, optional, tag = "1")]
        pub q_name: ::core::option::Option<::prost::alloc::string::String>,
        ///
        #[prost(uint32, optional, tag = "2")]
        pub q_type: ::core::option::Option<u32>,
        /// Usually 1 (IN)
        #[prost(uint32, optional, tag = "3")]
        pub q_class: ::core::option::Option<u32>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DnsResponse {
        #[prost(uint32, optional, tag = "1")]
        pub rcode: ::core::option::Option<u32>,
        #[prost(message, repeated, tag = "2")]
        pub rrs: ::prost::alloc::vec::Vec<dns_response::Dnsrr>,
    }
    /// Nested message and enum types in `DNSResponse`.
    pub mod dns_response {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Dnsrr {
            #[prost(string, optional, tag = "5")]
            pub rdata: ::core::option::Option<::prost::alloc::string::String>,
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DnsRequest {
    #[prost(string, tag = "1")]
    pub query: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DnsReply {
    #[prost(string, tag = "1")]
    pub reply: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DomainsList {
    #[prost(message, repeated, tag = "1")]
    pub domains: ::prost::alloc::vec::Vec<Domain>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Domain {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub created: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag = "4")]
    pub updated: ::core::option::Option<::prost_types::Timestamp>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DomainDeletion {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DomainDeletionResult {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsoleInput {
    #[prost(string, tag = "1")]
    pub input: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsoleOutput {
    #[prost(string, tag = "1")]
    pub output: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceEvent {
    #[prost(string, tag = "1")]
    pub event: ::prost::alloc::string::String,
}
/// Primitives
#[derive(serde::Serialize, Clone, PartialEq, ::prost::Message)]
pub struct Uuid {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VpcSearchQuery {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
    #[prost(string, optional, tag = "2")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Vpc {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub organization: ::core::option::Option<Uuid>,
    #[prost(message, optional, tag = "4")]
    pub created: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag = "5")]
    pub updated: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag = "6")]
    pub deleted: ::core::option::Option<::prost_types::Timestamp>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VpcDeletion {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VpcDeletionResult {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VpcList {
    #[prost(message, repeated, tag = "1")]
    pub vpcs: ::prost::alloc::vec::Vec<Vpc>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkSegment {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
    #[prost(message, optional, tag = "2")]
    pub vpc_id: ::core::option::Option<Uuid>,
    #[prost(string, tag = "3")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "4")]
    pub subdomain_id: ::core::option::Option<Uuid>,
    #[prost(int32, optional, tag = "5")]
    pub mtu: ::core::option::Option<i32>,
    #[prost(message, repeated, tag = "6")]
    pub prefixes: ::prost::alloc::vec::Vec<NetworkPrefix>,
    #[prost(message, optional, tag = "11")]
    pub created: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag = "12")]
    pub updated: ::core::option::Option<::prost_types::Timestamp>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkPrefix {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
    #[prost(string, tag = "2")]
    pub prefix: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "3")]
    pub gateway: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, tag = "4")]
    pub reserve_first: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkSegmentDeletion {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkSegmentQuery {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
}
#[derive(serde::Serialize, Clone, PartialEq, ::prost::Message)]
pub struct MachineState {
    #[prost(string, tag = "1")]
    pub state: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkSegmentDeletionResult {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstancePowerRequest {
    #[prost(message, optional, tag = "1")]
    pub machine_id: ::core::option::Option<Uuid>,
}
/// Nested message and enum types in `InstancePowerRequest`.
pub mod instance_power_request {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Operation {
        PowerOff = 0,
        PowerOn = 1,
        PowerReset = 2,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceType {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
    #[prost(string, tag = "2")]
    pub short_name: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub description: ::prost::alloc::string::String,
    #[prost(enumeration = "InstanceTypeCapabilities", repeated, tag = "4")]
    pub capabilities: ::prost::alloc::vec::Vec<i32>,
    #[prost(bool, tag = "5")]
    pub active: bool,
    #[prost(message, optional, tag = "6")]
    pub created: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag = "7")]
    pub updated: ::core::option::Option<::prost_types::Timestamp>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceTypeDeletion {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstancePowerResult {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceTypeDeletionResult {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Instance {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
    #[prost(message, optional, tag = "2")]
    pub segment_id: ::core::option::Option<Uuid>,
    #[prost(message, optional, tag = "3")]
    pub machine_id: ::core::option::Option<Uuid>,
    #[prost(message, optional, tag = "4")]
    pub operating_system: ::core::option::Option<OperatingSystem>,
    #[prost(string, optional, tag = "5")]
    pub user_data: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "6")]
    pub custom_ipxe: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag = "7")]
    pub ssh_keys: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "8")]
    pub requested: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag = "9")]
    pub started: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag = "10")]
    pub finished: ::core::option::Option<::prost_types::Timestamp>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OperatingSystem {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceDeletionRequest {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceDeletionResult {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MachineList {
    #[prost(message, repeated, tag = "1")]
    pub machines: ::prost::alloc::vec::Vec<Machine>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MachineSearchQuery {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
    #[prost(string, optional, tag = "2")]
    pub fqdn: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InterfaceList {
    #[prost(message, repeated, tag = "1")]
    pub interfaces: ::prost::alloc::vec::Vec<MachineInterface>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InterfaceSearchQuery {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Machine {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
    #[prost(message, optional, tag = "2")]
    pub supported_instance_type: ::core::option::Option<InstanceType>,
    #[prost(message, optional, tag = "3")]
    pub created: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag = "4")]
    pub updated: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag = "5")]
    pub deployed: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(string, tag = "6")]
    pub state: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "7")]
    pub events: ::prost::alloc::vec::Vec<MachineEvent>,
    #[prost(message, repeated, tag = "8")]
    pub interfaces: ::prost::alloc::vec::Vec<MachineInterface>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MachineEvent {
    #[prost(int64, tag = "1")]
    pub id: i64,
    #[prost(message, optional, tag = "2")]
    pub machine_id: ::core::option::Option<Uuid>,
    #[prost(enumeration = "MachineAction", tag = "3")]
    pub event: i32,
    #[prost(message, optional, tag = "4")]
    pub time: ::core::option::Option<::prost_types::Timestamp>,
}
#[derive(serde::Serialize, Clone, PartialEq, ::prost::Message)]
pub struct MachineInterface {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<Uuid>,
    #[prost(message, optional, tag = "2")]
    pub machine_id: ::core::option::Option<Uuid>,
    #[prost(message, optional, tag = "3")]
    pub segment_id: ::core::option::Option<Uuid>,
    #[prost(string, tag = "4")]
    pub hostname: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "5")]
    pub domain_id: ::core::option::Option<Uuid>,
    #[prost(bool, tag = "6")]
    pub primary_interface: bool,
    #[prost(string, tag = "7")]
    pub mac_address: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "8")]
    pub address: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DhcpDiscovery {
    #[prost(string, tag = "1")]
    pub mac_address: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub relay_address: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DhcpRecord {
    #[prost(message, optional, tag = "1")]
    pub machine_id: ::core::option::Option<Uuid>,
    #[prost(message, optional, tag = "2")]
    pub machine_interface_id: ::core::option::Option<Uuid>,
    #[prost(message, optional, tag = "3")]
    pub segment_id: ::core::option::Option<Uuid>,
    #[prost(message, optional, tag = "4")]
    pub subdomain_id: ::core::option::Option<Uuid>,
    #[prost(string, tag = "5")]
    pub fqdn: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub mac_address: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub address: ::prost::alloc::string::String,
    #[prost(int32, tag = "8")]
    pub mtu: i32,
    #[prost(string, tag = "9")]
    pub prefix: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "10")]
    pub gateway: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkSegmentList {
    #[prost(message, repeated, tag = "1")]
    pub network_segments: ::prost::alloc::vec::Vec<NetworkSegment>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Tag {
    #[prost(string, tag = "1")]
    pub slug: ::prost::alloc::string::String,
    /// Mandatory in case of CREATE action.
    #[prost(string, optional, tag = "3")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TagCreate {
    #[prost(message, optional, tag = "1")]
    pub tag: ::core::option::Option<Tag>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TagDelete {
    #[prost(message, optional, tag = "1")]
    pub tag: ::core::option::Option<Tag>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TagResult {
    #[prost(bool, tag = "1")]
    pub result: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TagVoid {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TagsList {
    #[prost(string, repeated, tag = "1")]
    pub slugs: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "2")]
    pub target: ::core::option::Option<Uuid>,
    #[prost(enumeration = "TagTargetKind", tag = "3")]
    pub target_kind: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TagsListResult {
    #[prost(message, repeated, tag = "1")]
    pub tags: ::prost::alloc::vec::Vec<Tag>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TagAssign {
    #[prost(string, tag = "1")]
    pub slug: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub target: ::core::option::Option<Uuid>,
    #[prost(enumeration = "TagTargetKind", tag = "3")]
    pub target_kind: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TagRemove {
    #[prost(string, tag = "1")]
    pub slug: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub target: ::core::option::Option<Uuid>,
    #[prost(enumeration = "TagTargetKind", tag = "3")]
    pub target_kind: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MachineDiscoveryInfo {
    #[prost(message, optional, tag = "1")]
    pub machine_id: ::core::option::Option<Uuid>,
    #[prost(oneof = "machine_discovery_info::DiscoveryData", tags = "2")]
    pub discovery_data: ::core::option::Option<machine_discovery_info::DiscoveryData>,
}
/// Nested message and enum types in `MachineDiscoveryInfo`.
pub mod machine_discovery_info {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum DiscoveryData {
        #[prost(message, tag = "2")]
        InfoV0(super::super::super::machine_discovery::v0::DiscoveryInfo),
    }
}
/// This is returned to the discovery client from the API. Lets try not to put much in here unless we need it.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MachineDiscoveryResult {}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum InstanceTypeCapabilities {
    Default = 0,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum MachineAction {
    Unknown = 0,
    Discover = 1,
    Adopt = 2,
    Test = 3,
    Commission = 4,
    Assign = 5,
    Fail = 6,
    Decommission = 7,
    Recommission = 8,
    Unassign = 9,
    Release = 10,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum TagTargetKind {
    Machine = 0,
    NetworkSegment = 1,
}
#[doc = r" Generated client implementations."]
pub mod forge_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    #[derive(Debug, Clone)]
    pub struct ForgeClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl ForgeClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> ForgeClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> ForgeClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            ForgeClient::new(InterceptedService::new(inner, interceptor))
        }
        #[doc = r" Compress requests with `gzip`."]
        #[doc = r""]
        #[doc = r" This requires the server to support it otherwise it might respond with an"]
        #[doc = r" error."]
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        #[doc = r" Enable decompressing responses with `gzip`."]
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
        }
        #[doc = " Domain"]
        pub async fn create_domain(
            &mut self,
            request: impl tonic::IntoRequest<super::Domain>,
        ) -> Result<tonic::Response<super::Domain>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/CreateDomain");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn update_domain(
            &mut self,
            request: impl tonic::IntoRequest<super::Domain>,
        ) -> Result<tonic::Response<super::Domain>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/UpdateDomain");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn delete_domain(
            &mut self,
            request: impl tonic::IntoRequest<super::DomainDeletion>,
        ) -> Result<tonic::Response<super::DomainDeletionResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/DeleteDomain");
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " VPC"]
        pub async fn create_vpc(
            &mut self,
            request: impl tonic::IntoRequest<super::Vpc>,
        ) -> Result<tonic::Response<super::Vpc>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/CreateVpc");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn update_vpc(
            &mut self,
            request: impl tonic::IntoRequest<super::Vpc>,
        ) -> Result<tonic::Response<super::Vpc>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/UpdateVpc");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn delete_vpc(
            &mut self,
            request: impl tonic::IntoRequest<super::VpcDeletion>,
        ) -> Result<tonic::Response<super::VpcDeletionResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/DeleteVpc");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn find_vpcs(
            &mut self,
            request: impl tonic::IntoRequest<super::VpcSearchQuery>,
        ) -> Result<tonic::Response<super::VpcList>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/FindVpcs");
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Segments - i.e. Overlay Networks"]
        pub async fn find_network_segments(
            &mut self,
            request: impl tonic::IntoRequest<super::NetworkSegmentQuery>,
        ) -> Result<tonic::Response<super::NetworkSegmentList>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/FindNetworkSegments");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn create_network_segment(
            &mut self,
            request: impl tonic::IntoRequest<super::NetworkSegment>,
        ) -> Result<tonic::Response<super::NetworkSegment>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/CreateNetworkSegment");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn update_network_segment(
            &mut self,
            request: impl tonic::IntoRequest<super::NetworkSegment>,
        ) -> Result<tonic::Response<super::NetworkSegment>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/UpdateNetworkSegment");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn delete_network_segment(
            &mut self,
            request: impl tonic::IntoRequest<super::NetworkSegmentDeletion>,
        ) -> Result<tonic::Response<super::NetworkSegmentDeletionResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/DeleteNetworkSegment");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn network_segments_for_vpc(
            &mut self,
            request: impl tonic::IntoRequest<super::VpcSearchQuery>,
        ) -> Result<tonic::Response<super::NetworkSegmentList>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/forge.v0.Forge/NetworkSegmentsForVpc");
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Manage instances on machines"]
        pub async fn create_instance(
            &mut self,
            request: impl tonic::IntoRequest<super::Instance>,
        ) -> Result<tonic::Response<super::Instance>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/CreateInstance");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn update_instance(
            &mut self,
            request: impl tonic::IntoRequest<super::Instance>,
        ) -> Result<tonic::Response<super::Instance>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/UpdateInstance");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn delete_instance(
            &mut self,
            request: impl tonic::IntoRequest<super::InstanceDeletionRequest>,
        ) -> Result<tonic::Response<super::InstanceDeletionResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/DeleteInstance");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn lookup_record(
            &mut self,
            request: impl tonic::IntoRequest<super::dns_message::DnsQuestion>,
        ) -> Result<tonic::Response<super::dns_message::DnsResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/LookupRecord");
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Power Control "]
        pub async fn invoke_instance_power(
            &mut self,
            request: impl tonic::IntoRequest<super::InstancePowerRequest>,
        ) -> Result<tonic::Response<super::InstancePowerResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/InvokeInstancePower");
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " PRIVILEGED: Creates a new machine from nothing"]
        pub async fn discover_machine(
            &mut self,
            request: impl tonic::IntoRequest<super::MachineDiscoveryInfo>,
        ) -> Result<tonic::Response<super::MachineDiscoveryResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/DiscoverMachine");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn discover_dhcp(
            &mut self,
            request: impl tonic::IntoRequest<super::DhcpDiscovery>,
        ) -> Result<tonic::Response<super::DhcpRecord>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/DiscoverDhcp");
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " PRIVILEGED: Get a single machine"]
        pub async fn get_machine(
            &mut self,
            request: impl tonic::IntoRequest<super::Uuid>,
        ) -> Result<tonic::Response<super::Machine>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/GetMachine");
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " PRIVILEGED: Find a list of machines"]
        pub async fn find_machines(
            &mut self,
            request: impl tonic::IntoRequest<super::MachineSearchQuery>,
        ) -> Result<tonic::Response<super::MachineList>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/FindMachines");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn find_interfaces(
            &mut self,
            request: impl tonic::IntoRequest<super::InterfaceSearchQuery>,
        ) -> Result<tonic::Response<super::InterfaceList>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/FindInterfaces");
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " PRIVILEGED: Define and manage new instance types"]
        pub async fn create_instance_type(
            &mut self,
            request: impl tonic::IntoRequest<super::InstanceType>,
        ) -> Result<tonic::Response<super::InstanceType>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/CreateInstanceType");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn update_instance_type(
            &mut self,
            request: impl tonic::IntoRequest<super::InstanceType>,
        ) -> Result<tonic::Response<super::InstanceType>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/UpdateInstanceType");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn delete_instance_type(
            &mut self,
            request: impl tonic::IntoRequest<super::InstanceTypeDeletion>,
        ) -> Result<tonic::Response<super::InstanceTypeDeletionResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/DeleteInstanceType");
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Tags handling"]
        pub async fn create_tag(
            &mut self,
            request: impl tonic::IntoRequest<super::TagCreate>,
        ) -> Result<tonic::Response<super::TagResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/CreateTag");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn delete_tag(
            &mut self,
            request: impl tonic::IntoRequest<super::TagDelete>,
        ) -> Result<tonic::Response<super::TagResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/DeleteTag");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn list_tags(
            &mut self,
            request: impl tonic::IntoRequest<super::TagVoid>,
        ) -> Result<tonic::Response<super::TagsListResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/ListTags");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn assign_tag(
            &mut self,
            request: impl tonic::IntoRequest<super::TagAssign>,
        ) -> Result<tonic::Response<super::TagResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/AssignTag");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn remove_tag(
            &mut self,
            request: impl tonic::IntoRequest<super::TagRemove>,
        ) -> Result<tonic::Response<super::TagResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/RemoveTag");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn set_tags(
            &mut self,
            request: impl tonic::IntoRequest<super::TagsList>,
        ) -> Result<tonic::Response<super::TagResult>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/forge.v0.Forge/SetTags");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
#[doc = r" Generated server implementations."]
pub mod forge_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    #[doc = "Generated trait containing gRPC methods that should be implemented for use with ForgeServer."]
    #[async_trait]
    pub trait Forge: Send + Sync + 'static {
        #[doc = " Domain"]
        async fn create_domain(
            &self,
            request: tonic::Request<super::Domain>,
        ) -> Result<tonic::Response<super::Domain>, tonic::Status>;
        async fn update_domain(
            &self,
            request: tonic::Request<super::Domain>,
        ) -> Result<tonic::Response<super::Domain>, tonic::Status>;
        async fn delete_domain(
            &self,
            request: tonic::Request<super::DomainDeletion>,
        ) -> Result<tonic::Response<super::DomainDeletionResult>, tonic::Status>;
        #[doc = " VPC"]
        async fn create_vpc(
            &self,
            request: tonic::Request<super::Vpc>,
        ) -> Result<tonic::Response<super::Vpc>, tonic::Status>;
        async fn update_vpc(
            &self,
            request: tonic::Request<super::Vpc>,
        ) -> Result<tonic::Response<super::Vpc>, tonic::Status>;
        async fn delete_vpc(
            &self,
            request: tonic::Request<super::VpcDeletion>,
        ) -> Result<tonic::Response<super::VpcDeletionResult>, tonic::Status>;
        async fn find_vpcs(
            &self,
            request: tonic::Request<super::VpcSearchQuery>,
        ) -> Result<tonic::Response<super::VpcList>, tonic::Status>;
        #[doc = " Segments - i.e. Overlay Networks"]
        async fn find_network_segments(
            &self,
            request: tonic::Request<super::NetworkSegmentQuery>,
        ) -> Result<tonic::Response<super::NetworkSegmentList>, tonic::Status>;
        async fn create_network_segment(
            &self,
            request: tonic::Request<super::NetworkSegment>,
        ) -> Result<tonic::Response<super::NetworkSegment>, tonic::Status>;
        async fn update_network_segment(
            &self,
            request: tonic::Request<super::NetworkSegment>,
        ) -> Result<tonic::Response<super::NetworkSegment>, tonic::Status>;
        async fn delete_network_segment(
            &self,
            request: tonic::Request<super::NetworkSegmentDeletion>,
        ) -> Result<tonic::Response<super::NetworkSegmentDeletionResult>, tonic::Status>;
        async fn network_segments_for_vpc(
            &self,
            request: tonic::Request<super::VpcSearchQuery>,
        ) -> Result<tonic::Response<super::NetworkSegmentList>, tonic::Status>;
        #[doc = " Manage instances on machines"]
        async fn create_instance(
            &self,
            request: tonic::Request<super::Instance>,
        ) -> Result<tonic::Response<super::Instance>, tonic::Status>;
        async fn update_instance(
            &self,
            request: tonic::Request<super::Instance>,
        ) -> Result<tonic::Response<super::Instance>, tonic::Status>;
        async fn delete_instance(
            &self,
            request: tonic::Request<super::InstanceDeletionRequest>,
        ) -> Result<tonic::Response<super::InstanceDeletionResult>, tonic::Status>;
        async fn lookup_record(
            &self,
            request: tonic::Request<super::dns_message::DnsQuestion>,
        ) -> Result<tonic::Response<super::dns_message::DnsResponse>, tonic::Status>;
        #[doc = " Power Control "]
        async fn invoke_instance_power(
            &self,
            request: tonic::Request<super::InstancePowerRequest>,
        ) -> Result<tonic::Response<super::InstancePowerResult>, tonic::Status>;
        #[doc = " PRIVILEGED: Creates a new machine from nothing"]
        async fn discover_machine(
            &self,
            request: tonic::Request<super::MachineDiscoveryInfo>,
        ) -> Result<tonic::Response<super::MachineDiscoveryResult>, tonic::Status>;
        async fn discover_dhcp(
            &self,
            request: tonic::Request<super::DhcpDiscovery>,
        ) -> Result<tonic::Response<super::DhcpRecord>, tonic::Status>;
        #[doc = " PRIVILEGED: Get a single machine"]
        async fn get_machine(
            &self,
            request: tonic::Request<super::Uuid>,
        ) -> Result<tonic::Response<super::Machine>, tonic::Status>;
        #[doc = " PRIVILEGED: Find a list of machines"]
        async fn find_machines(
            &self,
            request: tonic::Request<super::MachineSearchQuery>,
        ) -> Result<tonic::Response<super::MachineList>, tonic::Status>;
        async fn find_interfaces(
            &self,
            request: tonic::Request<super::InterfaceSearchQuery>,
        ) -> Result<tonic::Response<super::InterfaceList>, tonic::Status>;
        #[doc = " PRIVILEGED: Define and manage new instance types"]
        async fn create_instance_type(
            &self,
            request: tonic::Request<super::InstanceType>,
        ) -> Result<tonic::Response<super::InstanceType>, tonic::Status>;
        async fn update_instance_type(
            &self,
            request: tonic::Request<super::InstanceType>,
        ) -> Result<tonic::Response<super::InstanceType>, tonic::Status>;
        async fn delete_instance_type(
            &self,
            request: tonic::Request<super::InstanceTypeDeletion>,
        ) -> Result<tonic::Response<super::InstanceTypeDeletionResult>, tonic::Status>;
        #[doc = " Tags handling"]
        async fn create_tag(
            &self,
            request: tonic::Request<super::TagCreate>,
        ) -> Result<tonic::Response<super::TagResult>, tonic::Status>;
        async fn delete_tag(
            &self,
            request: tonic::Request<super::TagDelete>,
        ) -> Result<tonic::Response<super::TagResult>, tonic::Status>;
        async fn list_tags(
            &self,
            request: tonic::Request<super::TagVoid>,
        ) -> Result<tonic::Response<super::TagsListResult>, tonic::Status>;
        async fn assign_tag(
            &self,
            request: tonic::Request<super::TagAssign>,
        ) -> Result<tonic::Response<super::TagResult>, tonic::Status>;
        async fn remove_tag(
            &self,
            request: tonic::Request<super::TagRemove>,
        ) -> Result<tonic::Response<super::TagResult>, tonic::Status>;
        async fn set_tags(
            &self,
            request: tonic::Request<super::TagsList>,
        ) -> Result<tonic::Response<super::TagResult>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct ForgeServer<T: Forge> {
        inner: _Inner<T>,
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Forge> ForgeServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for ForgeServer<T>
    where
        T: Forge,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/forge.v0.Forge/CreateDomain" => {
                    #[allow(non_camel_case_types)]
                    struct CreateDomainSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::Domain> for CreateDomainSvc<T> {
                        type Response = super::Domain;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(&mut self, request: tonic::Request<super::Domain>) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).create_domain(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = CreateDomainSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/UpdateDomain" => {
                    #[allow(non_camel_case_types)]
                    struct UpdateDomainSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::Domain> for UpdateDomainSvc<T> {
                        type Response = super::Domain;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(&mut self, request: tonic::Request<super::Domain>) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).update_domain(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = UpdateDomainSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/DeleteDomain" => {
                    #[allow(non_camel_case_types)]
                    struct DeleteDomainSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::DomainDeletion> for DeleteDomainSvc<T> {
                        type Response = super::DomainDeletionResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DomainDeletion>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).delete_domain(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DeleteDomainSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/CreateVpc" => {
                    #[allow(non_camel_case_types)]
                    struct CreateVpcSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::Vpc> for CreateVpcSvc<T> {
                        type Response = super::Vpc;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(&mut self, request: tonic::Request<super::Vpc>) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).create_vpc(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = CreateVpcSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/UpdateVpc" => {
                    #[allow(non_camel_case_types)]
                    struct UpdateVpcSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::Vpc> for UpdateVpcSvc<T> {
                        type Response = super::Vpc;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(&mut self, request: tonic::Request<super::Vpc>) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).update_vpc(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = UpdateVpcSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/DeleteVpc" => {
                    #[allow(non_camel_case_types)]
                    struct DeleteVpcSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::VpcDeletion> for DeleteVpcSvc<T> {
                        type Response = super::VpcDeletionResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::VpcDeletion>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).delete_vpc(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DeleteVpcSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/FindVpcs" => {
                    #[allow(non_camel_case_types)]
                    struct FindVpcsSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::VpcSearchQuery> for FindVpcsSvc<T> {
                        type Response = super::VpcList;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::VpcSearchQuery>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).find_vpcs(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = FindVpcsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/FindNetworkSegments" => {
                    #[allow(non_camel_case_types)]
                    struct FindNetworkSegmentsSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::NetworkSegmentQuery>
                        for FindNetworkSegmentsSvc<T>
                    {
                        type Response = super::NetworkSegmentList;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::NetworkSegmentQuery>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).find_network_segments(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = FindNetworkSegmentsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/CreateNetworkSegment" => {
                    #[allow(non_camel_case_types)]
                    struct CreateNetworkSegmentSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::NetworkSegment> for CreateNetworkSegmentSvc<T> {
                        type Response = super::NetworkSegment;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::NetworkSegment>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).create_network_segment(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = CreateNetworkSegmentSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/UpdateNetworkSegment" => {
                    #[allow(non_camel_case_types)]
                    struct UpdateNetworkSegmentSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::NetworkSegment> for UpdateNetworkSegmentSvc<T> {
                        type Response = super::NetworkSegment;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::NetworkSegment>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).update_network_segment(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = UpdateNetworkSegmentSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/DeleteNetworkSegment" => {
                    #[allow(non_camel_case_types)]
                    struct DeleteNetworkSegmentSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::NetworkSegmentDeletion>
                        for DeleteNetworkSegmentSvc<T>
                    {
                        type Response = super::NetworkSegmentDeletionResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::NetworkSegmentDeletion>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).delete_network_segment(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DeleteNetworkSegmentSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/NetworkSegmentsForVpc" => {
                    #[allow(non_camel_case_types)]
                    struct NetworkSegmentsForVpcSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::VpcSearchQuery> for NetworkSegmentsForVpcSvc<T> {
                        type Response = super::NetworkSegmentList;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::VpcSearchQuery>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut =
                                async move { (*inner).network_segments_for_vpc(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = NetworkSegmentsForVpcSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/CreateInstance" => {
                    #[allow(non_camel_case_types)]
                    struct CreateInstanceSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::Instance> for CreateInstanceSvc<T> {
                        type Response = super::Instance;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Instance>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).create_instance(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = CreateInstanceSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/UpdateInstance" => {
                    #[allow(non_camel_case_types)]
                    struct UpdateInstanceSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::Instance> for UpdateInstanceSvc<T> {
                        type Response = super::Instance;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Instance>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).update_instance(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = UpdateInstanceSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/DeleteInstance" => {
                    #[allow(non_camel_case_types)]
                    struct DeleteInstanceSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::InstanceDeletionRequest>
                        for DeleteInstanceSvc<T>
                    {
                        type Response = super::InstanceDeletionResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::InstanceDeletionRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).delete_instance(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DeleteInstanceSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/LookupRecord" => {
                    #[allow(non_camel_case_types)]
                    struct LookupRecordSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::dns_message::DnsQuestion> for LookupRecordSvc<T> {
                        type Response = super::dns_message::DnsResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::dns_message::DnsQuestion>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).lookup_record(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = LookupRecordSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/InvokeInstancePower" => {
                    #[allow(non_camel_case_types)]
                    struct InvokeInstancePowerSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::InstancePowerRequest>
                        for InvokeInstancePowerSvc<T>
                    {
                        type Response = super::InstancePowerResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::InstancePowerRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).invoke_instance_power(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = InvokeInstancePowerSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/DiscoverMachine" => {
                    #[allow(non_camel_case_types)]
                    struct DiscoverMachineSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::MachineDiscoveryInfo> for DiscoverMachineSvc<T> {
                        type Response = super::MachineDiscoveryResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::MachineDiscoveryInfo>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).discover_machine(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DiscoverMachineSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/DiscoverDhcp" => {
                    #[allow(non_camel_case_types)]
                    struct DiscoverDhcpSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::DhcpDiscovery> for DiscoverDhcpSvc<T> {
                        type Response = super::DhcpRecord;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DhcpDiscovery>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).discover_dhcp(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DiscoverDhcpSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/GetMachine" => {
                    #[allow(non_camel_case_types)]
                    struct GetMachineSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::Uuid> for GetMachineSvc<T> {
                        type Response = super::Machine;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(&mut self, request: tonic::Request<super::Uuid>) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).get_machine(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetMachineSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/FindMachines" => {
                    #[allow(non_camel_case_types)]
                    struct FindMachinesSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::MachineSearchQuery> for FindMachinesSvc<T> {
                        type Response = super::MachineList;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::MachineSearchQuery>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).find_machines(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = FindMachinesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/FindInterfaces" => {
                    #[allow(non_camel_case_types)]
                    struct FindInterfacesSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::InterfaceSearchQuery> for FindInterfacesSvc<T> {
                        type Response = super::InterfaceList;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::InterfaceSearchQuery>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).find_interfaces(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = FindInterfacesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/CreateInstanceType" => {
                    #[allow(non_camel_case_types)]
                    struct CreateInstanceTypeSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::InstanceType> for CreateInstanceTypeSvc<T> {
                        type Response = super::InstanceType;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::InstanceType>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).create_instance_type(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = CreateInstanceTypeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/UpdateInstanceType" => {
                    #[allow(non_camel_case_types)]
                    struct UpdateInstanceTypeSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::InstanceType> for UpdateInstanceTypeSvc<T> {
                        type Response = super::InstanceType;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::InstanceType>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).update_instance_type(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = UpdateInstanceTypeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/DeleteInstanceType" => {
                    #[allow(non_camel_case_types)]
                    struct DeleteInstanceTypeSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::InstanceTypeDeletion>
                        for DeleteInstanceTypeSvc<T>
                    {
                        type Response = super::InstanceTypeDeletionResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::InstanceTypeDeletion>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).delete_instance_type(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DeleteInstanceTypeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/CreateTag" => {
                    #[allow(non_camel_case_types)]
                    struct CreateTagSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::TagCreate> for CreateTagSvc<T> {
                        type Response = super::TagResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::TagCreate>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).create_tag(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = CreateTagSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/DeleteTag" => {
                    #[allow(non_camel_case_types)]
                    struct DeleteTagSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::TagDelete> for DeleteTagSvc<T> {
                        type Response = super::TagResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::TagDelete>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).delete_tag(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DeleteTagSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/ListTags" => {
                    #[allow(non_camel_case_types)]
                    struct ListTagsSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::TagVoid> for ListTagsSvc<T> {
                        type Response = super::TagsListResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::TagVoid>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).list_tags(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = ListTagsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/AssignTag" => {
                    #[allow(non_camel_case_types)]
                    struct AssignTagSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::TagAssign> for AssignTagSvc<T> {
                        type Response = super::TagResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::TagAssign>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).assign_tag(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = AssignTagSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/RemoveTag" => {
                    #[allow(non_camel_case_types)]
                    struct RemoveTagSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::TagRemove> for RemoveTagSvc<T> {
                        type Response = super::TagResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::TagRemove>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).remove_tag(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = RemoveTagSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/forge.v0.Forge/SetTags" => {
                    #[allow(non_camel_case_types)]
                    struct SetTagsSvc<T: Forge>(pub Arc<T>);
                    impl<T: Forge> tonic::server::UnaryService<super::TagsList> for SetTagsSvc<T> {
                        type Response = super::TagResult;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::TagsList>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).set_tags(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = SetTagsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Forge> Clone for ForgeServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: Forge> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Forge> tonic::transport::NamedService for ForgeServer<T> {
        const NAME: &'static str = "forge.v0.Forge";
    }
}
