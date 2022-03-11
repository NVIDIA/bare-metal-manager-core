//! Carbide gRPC and protobuf module
//!
//! This module contains the gRPC and protocol buffer definitions to generate a client or server to
//! interact with the API Service
//!
pub mod v0 {
    use mac_address::{MacAddress, MacParseError};
    use prost::Message;
    use serde::Serialize;
    use std::convert::From;
    use std::convert::TryFrom;
    use std::fmt::Display;
    use std::str::FromStr;

    use serde::ser::SerializeStruct;

    pub use prost_types::Timestamp;

    // In order for CLion to grok the generated files, we need to use include! instead of
    // tonic's built in include. To include the proto build in CLion, ensure that the experimental
    // `org.rust.cargo.evaluate.build.scripts` flag is enabled.
    include!(concat!(env!("OUT_DIR"), "/metal.v0.rs"));

    pub const REFLECTION_SERVICE_DESCRIPTOR: &[u8] =
        tonic::include_file_descriptor_set!("metal.v0");

    pub fn get_encoded_reflection_service_fd() -> Vec<u8> {
        let mut expected = Vec::new();
        prost_types::FileDescriptorSet::decode(REFLECTION_SERVICE_DESCRIPTOR)
            .expect("decode reflection service file descriptor set")
            .file[0]
            .encode(&mut expected)
            .expect("encode reflection service file descriptor");
        expected
    }

    impl Serialize for MachineEvent {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut state = serializer.serialize_struct("MachineEvent", 5)?;

            state.serialize_field("id", &self.id)?;
            state.serialize_field("machine_id", &self.machine_id)?;
            state.serialize_field("event", &self.event)?;
            state.serialize_field("version", &self.version)?;
            state.serialize_field("time", &self.time.as_ref().map(|ts| ts.seconds))?;

            state.end()
        }
    }

    impl Serialize for Domain {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut state = serializer.serialize_struct("Domain", 4)?;

            state.serialize_field("id", &self.id)?;
            state.serialize_field("name", &self.name)?;
            state.serialize_field("created", &self.created.as_ref().map(|ts| ts.seconds))?;
            state.serialize_field("updated", &self.updated.as_ref().map(|ts| ts.seconds))?;
            state.end()
        }
    }
    impl Serialize for Machine {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut state = serializer.serialize_struct("Machine", 8)?;

            state.serialize_field("id", &self.id)?;
            //state.serialize_field("fqdn", &self.fqdn)?;
            state.serialize_field("created", &self.created.as_ref().map(|ts| ts.seconds))?;
            state.serialize_field("modified", &self.updated.as_ref().map(|ts| ts.seconds))?;
            state.serialize_field("events", &self.events)?;
            state.serialize_field("interfaces", &self.interfaces)?;
            state.serialize_field("state", &self.state)?;

            state.end()
        }
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
                Err(err) => write!(f, "<uuid error: {}>", err),
            }
        }
    }

    impl MachineInterface {
        pub fn parsed_mac_address(&self) -> Result<Option<MacAddress>, MacParseError> {
            Ok(Some(MacAddress::from_str(&self.mac_address)?))
        }
    }
}
