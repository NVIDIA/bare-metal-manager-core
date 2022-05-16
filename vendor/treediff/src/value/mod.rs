//! Contains all implementations of the `Value` and `Mutable` traits.
//!
//! Note that these are behind feature flags.
mod shared;
pub use self::shared::*;

#[cfg(feature = "with-rustc-serialize")]
mod rustc_json;

#[cfg(feature = "with-serde-json")]
mod serde_json;

#[cfg(feature = "with-serde-yaml")]
mod serde_yaml;

#[cfg(feature = "with-yaml-rust")]
mod yaml_rust;
