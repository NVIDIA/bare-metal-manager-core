#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DiscoveryInfo {
    #[prost(message, repeated, tag = "1")]
    pub network_interfaces: ::prost::alloc::vec::Vec<NetworkInterface>,
    #[prost(message, repeated, tag = "2")]
    pub cpus: ::prost::alloc::vec::Vec<Cpu>,
    #[prost(message, repeated, tag = "3")]
    pub block_devices: ::prost::alloc::vec::Vec<BlockDevice>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkInterface {
    #[prost(string, tag = "1")]
    pub mac_address: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub pci_properties: ::core::option::Option<PciDeviceProperties>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Cpu {
    #[prost(string, tag = "1")]
    pub vendor: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub model: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub frequency: ::prost::alloc::string::String,
    #[prost(uint32, tag = "4")]
    pub number: u32,
    #[prost(uint32, tag = "5")]
    pub core: u32,
    #[prost(int32, tag = "6")]
    pub node: i32,
    #[prost(uint32, tag = "7")]
    pub socket: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockDevice {
    #[prost(string, tag = "1")]
    pub model: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub revision: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub serial: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PciDeviceProperties {
    #[prost(string, tag = "1")]
    pub vendor: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub device: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub path: ::prost::alloc::string::String,
    #[prost(sint32, tag = "4")]
    pub numa_node: i32,
    #[prost(string, optional, tag = "5")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
}
