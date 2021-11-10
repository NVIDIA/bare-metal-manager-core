//! Carbide gRPC and protobuf module
//!
//! This module contains the gRPC and protocol buffer definitions to generate a client or server to
//! interact with the API Service
//!
pub mod v0 {
    use prost::Message;
    use std::convert::From;
    use std::convert::TryFrom;
    use std::net::{Ipv4Addr, Ipv6Addr, AddrParseError};
    use std::str::FromStr;
    use std::fmt::Display;
    use eui48::{ParseError, MacAddress};

    tonic::include_proto!("carbide.v0");

    pub const REFLECTION_SERVICE_DESCRIPTOR: &[u8] =
        tonic::include_file_descriptor_set!("carbide.v0");

    pub fn get_encoded_reflection_service_fd() -> Vec<u8> {
        let mut expected = Vec::new();
        prost_types::FileDescriptorSet::decode(REFLECTION_SERVICE_DESCRIPTOR)
            .expect("decode reflection service file descriptor set")
            .file[0]
            .encode(&mut expected)
            .expect("encode reflection service file descriptor");
        expected
    }

    impl From<uuid::Uuid> for Uuid {
        fn from(uuid: uuid::Uuid) -> Uuid {
            Uuid {
                value: uuid.to_hyphenated().to_string(),
            }
        }
    }

    impl TryFrom<Uuid> for uuid::Uuid {
        type Error = uuid::Error;
        fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
            uuid::Uuid::parse_str(&uuid.value)
        }
    }

    impl TryFrom<&Uuid> for uuid::Uuid {
        type Error = uuid::Error;
        fn try_from(uuid: &Uuid) -> Result<Self, Self::Error> {
            uuid::Uuid::parse_str(&uuid.value)
        }
    }

    impl Display for Uuid {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match uuid::Uuid::try_from(self) {
                Ok(uuid) => write!(f, "{}", uuid),
                Err(err) => write!(f, "<uuid error: {}", err),
            }
        }
    }

    impl MachineInterface {
        pub fn parsed_address_ipv4(&self) -> Result<Option<Ipv4Addr>, AddrParseError> {
            if let Some(addr) = &self.address_ipv4 {
                Ok(Some(Ipv4Addr::from_str(&addr)?))
            } else {
                Ok(None)
            }
        }

        pub fn parsed_address_ipv6(&self) -> Result<Option<Ipv6Addr>, AddrParseError> {
            if let Some(addr) = &self.address_ipv6 {
                Ok(Some(Ipv6Addr::from_str(&addr)?))
            } else {
                Ok(None)
            }
        }

        pub fn parsed_mac_address(&self) -> Result<Option<MacAddress>, ParseError> {
            Ok(Some(MacAddress::from_str(&self.mac_address)?))
        }
    }
}
