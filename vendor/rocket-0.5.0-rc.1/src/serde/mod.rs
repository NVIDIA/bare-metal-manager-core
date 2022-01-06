//! Automatic serialization and deserialization support.

#[doc(inline)]
pub use serde::ser::{Serialize, Serializer};

#[doc(inline)]
pub use serde::de::{Deserialize, DeserializeOwned, Deserializer};

#[doc(hidden)]
pub use serde::*;

#[cfg(feature = "json")]
#[cfg_attr(nightly, doc(cfg(feature = "json")))]
pub mod json;

#[cfg(feature = "msgpack")]
#[cfg_attr(nightly, doc(cfg(feature = "msgpack")))]
pub mod msgpack;

#[cfg(feature = "uuid")]
#[cfg_attr(nightly, doc(cfg(feature = "uuid")))]
pub mod uuid;
