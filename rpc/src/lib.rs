//! Carbide gRPC and protobuf module
//!
//! This module contains the gRPC and protocol buffer definitions to generate a client or server to
//! interact with the API Service
//!
pub mod v0 {
    use prost::Message;
    use std::convert::From;
    use std::convert::TryFrom;

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
}
