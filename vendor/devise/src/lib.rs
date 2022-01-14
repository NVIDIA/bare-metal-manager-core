extern crate devise_core;

// Magic incantantion to reexport proc-macros from codegen crate.
#[allow(unused_imports)] #[macro_use] extern crate devise_codegen;
#[doc(hidden)] pub use devise_codegen::*;

pub use devise_core::*;
