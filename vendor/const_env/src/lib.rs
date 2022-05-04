extern crate proc_macro;

use const_env_impl::RealEnv;
use proc_macro::TokenStream;

/// Configure a `const` or `static` item from an environment variable.
#[proc_macro_attribute]
pub fn from_env(attr: TokenStream, item: TokenStream) -> TokenStream {
    const_env_impl::from_env(attr.into(), item.into(), RealEnv {}).into()
}