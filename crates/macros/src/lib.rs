/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{LitStr, Meta, Token};

type AttributeArgs = syn::punctuated::Punctuated<syn::Meta, syn::Token![,]>;

/// Use this instead of `#[sqlx::test]`. This is because `#[sqlx::test]` inlines everything on every
/// usage, including:
///
/// - The entire migrations directory, inlined as a huge string constant
/// - Every fixture file you specify, as individual string constants
///
/// This ends up blowing up the test executable size tremendously, and causes link times to be very
/// long, even on incremental builds.
///
/// Using our own test wrapper macro fixes this by declaring fixtures in one static place, and referencing
/// them on every invocation instead. This is not possible for sqlx to do
/// natively, since every sqlx::test macro has to stand on its own and not assume any constants
/// are defined anywhere.
///
/// Also, this wrapper uses sqlx_testing library that creates database for all tests from the template
/// database (initialized using migrations) which is much more faster than migrate database on each
/// unit test start.
///
/// # Specifying fixtures
///
/// - Fixtures are specified with `#[carbide_macros::sqlx_test(fixtures("fixture1", ...))]` (or
///   wherever `crate::tests::sqlx_fixture_from_str` loads them.)
/// - All fixtures are relative to api/src/tests/fixtures.
///
/// This does not support other options from sqlx::test, e.g. `path`, `scripts(...)`, etc.
///
/// # Creating new fixtures
///
/// Add fixtures to api/src/tests/fixtures, and edit `crate::tests::sqlx_fixture_from_str` and add
/// the name of your fixture.
///
/// # How does it work?
///
/// By setting up a sqlx test to run migrations and fixtures the same way `sqlx::test` does, but by
/// hardcoding calls to our own migrator and fixtures, which can be made static and thus not
/// duplicated. It will expand to the following:
///
/// ```ignore
/// // before:
/// #[carbide_macros::sqlx_test(fixtures("my_fixture"))]
/// async fn the_test(pool: sqlx::PgPool) { /* the test */ }
///
/// // after:
/// #[test]
/// fn the_test() {
///     async fn the_test(pool: sqlx::PgPool) { /* test is "pasted" here */ }
///     let mut args = ::sqlx::testing::TestArgs::new("carbide::tests::the_test");
///     // NOTE: crate::tests::MIGRATOR must exist!
///     args.migrator(&crate::tests::MIGRATOR);
///     args.fixtures(
///         Box::leak(
///             Box::new(
///                 <[_]>::into_vec(
///                     #[rustc_box]
///                     ::alloc::boxed::Box::new([
///                         // NOTE: crate::tests::sqlx_fixture_from_str must exist!
///                         crate::tests::sqlx_fixture_from_str("create_domain"),
///                     ]),
///                 ),
///             ),
///         ),
///     );
///     let f: fn(_) -> _ = the_test;
///     ::sqlx::testing::TestFn::run_test(f, args)
///    }
/// }
/// ```
///
/// That is, it will hardcode calls to `crate::tests::sqlx_fixture_from_str` and
/// `crate::tests::MIGRATOR`. So this macro will only work of those are defined in your crate. The
/// reason for this is that it can allow defining a single static call to `sqlx::migrate!()` (which
/// dumps your entire migrations folder as string literals), and a single instance of
/// `include_str!("fixture.sql")` per fixture, and referencing them repeatedly, rather than dumping
/// string literals for each on every single test. This reduces the size of our test executable by
/// 90%.
#[proc_macro_attribute]
pub fn sqlx_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::ItemFn);
    match expand(args, input) {
        Ok(ts) => ts,
        Err(e) => {
            if let Some(parse_err) = e.downcast_ref::<syn::Error>() {
                parse_err.to_compile_error().into()
            } else {
                let msg = e.to_string();
                quote!(::std::compile_error!(#msg)).into()
            }
        }
    }
}

fn expand(args: TokenStream, input: syn::ItemFn) -> eyre::Result<TokenStream> {
    let ret = &input.sig.output;
    let name = &input.sig.ident;
    let inputs = &input.sig.inputs;
    let body = &input.block;
    let attrs = &input.attrs;

    let parser = AttributeArgs::parse_terminated;
    let args = parser.parse2(args.into())?;

    // Fixtures need to be types with exported paths (e.g. tests::fixtures::SomeFixture)
    let fixtures = args
        .into_iter()
        .filter_map(|arg| match arg {
            Meta::List(list) => {
                if list.path.is_ident("fixtures") {
                    let args = list
                        .parse_args_with(<Punctuated<LitStr, Token![,]>>::parse_terminated)
                        .ok()?;
                    Some(args)
                } else {
                    None
                }
            }
            _ => None,
        })
        .flat_map(|str_lits| {
            str_lits
                .iter()
                .map(|str_lit| quote! { crate::tests::sqlx_fixture_from_str(#str_lit) })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let fn_arg_types = inputs.iter().map(|_| quote! { _ });

    let pm2_token_stream = quote! {
        #(#attrs)*
        #[::core::prelude::v1::test]
        fn #name() #ret {
            async fn #name(#inputs) #ret {
                #body
            }

            let mut args = ::sqlx::testing::TestArgs::new(concat!(module_path!(), "::", stringify!(#name)));

            // Note: we use Box::leak because args.fixtures expects a &'static slice, which is
            // normally only possible if you define the fixtures inline. Since each TestFixture is a
            // struct with two `&'static str`s inside it, this should only leak 16 bytes per unit
            // test, which is fine. (We're not leaking the entire fixtures, just pointers to them.)
            args.fixtures(Box::leak(Box::new(vec![#(#fixtures),*])));

            // We need to give a coercion site or else we get "unimplemented trait" errors.
            let f: fn(#(#fn_arg_types),*) -> _ = #name;

            sqlx_testing::TestFn::run_test(f, args)
        }
    };
    Ok(pm2_token_stream.into())
}
