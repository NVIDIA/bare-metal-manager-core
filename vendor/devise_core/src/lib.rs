#![recursion_limit="256"]

#[macro_use] pub extern crate quote;
#[macro_use] extern crate bitflags;
pub extern crate syn;
pub extern crate proc_macro2;
pub extern crate proc_macro2_diagnostics;


#[macro_use] mod macros;
#[macro_use] pub mod mapper;
#[macro_use] pub mod validator;
mod field;
mod generator;
mod support;
mod derived;
mod from_meta;

pub mod ext;

pub use field::*;
pub use support::Support;
pub use generator::*;
pub use from_meta::*;
pub use derived::*;
pub use proc_macro2_diagnostics::{Diagnostic, Level};
pub use syn::spanned::Spanned;
pub use mapper::{Mapper, MapperBuild};
pub use validator::{Validator, ValidatorBuild};
