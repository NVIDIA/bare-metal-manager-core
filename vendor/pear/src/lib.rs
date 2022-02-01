#![warn(rust_2018_idioms)]

#[doc(hidden)] pub use inlinable_string;

#[macro_use] pub mod macros;
pub mod input;
pub mod result;
pub mod error;
pub mod parsers;
pub mod combinators;

mod expected;

#[doc(hidden)] pub mod debug;
