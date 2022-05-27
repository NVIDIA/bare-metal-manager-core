#![deny(missing_docs, unsafe_code)]
//! # sqlxmq_macros
//!
//! Provides procedural macros for the `sqlxmq` crate.

use std::mem;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, ToTokens, TokenStreamExt};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, parse_quote, AttrStyle, Attribute, AttributeArgs, Error, Lit, Meta,
    NestedMeta, Path, Result, Signature, Visibility,
};

#[derive(Default)]
struct JobOptions {
    proto: Option<Path>,
    name: Option<String>,
    channel_name: Option<String>,
    retries: Option<u32>,
    backoff_secs: Option<f64>,
    ordered: Option<bool>,
}

enum OptionValue<'a> {
    None,
    Lit(&'a Lit),
    Path(&'a Path),
}

fn interpret_job_arg(options: &mut JobOptions, arg: NestedMeta) -> Result<()> {
    fn error(arg: NestedMeta) -> Result<()> {
        Err(Error::new_spanned(arg, "Unexpected attribute argument"))
    }
    match &arg {
        NestedMeta::Lit(Lit::Str(s)) if options.name.is_none() => {
            options.name = Some(s.value());
        }
        NestedMeta::Meta(m) => {
            if let Some(ident) = m.path().get_ident() {
                let name = ident.to_string();
                let value = match &m {
                    Meta::List(l) => {
                        if let NestedMeta::Meta(Meta::Path(p)) = &l.nested[0] {
                            OptionValue::Path(p)
                        } else {
                            return error(arg);
                        }
                    }
                    Meta::Path(_) => OptionValue::None,
                    Meta::NameValue(nvp) => OptionValue::Lit(&nvp.lit),
                };
                match (name.as_str(), value) {
                    ("proto", OptionValue::Path(p)) if options.proto.is_none() => {
                        options.proto = Some(p.clone());
                    }
                    ("name", OptionValue::Lit(Lit::Str(s))) if options.name.is_none() => {
                        options.name = Some(s.value());
                    }
                    ("channel_name", OptionValue::Lit(Lit::Str(s)))
                        if options.channel_name.is_none() =>
                    {
                        options.channel_name = Some(s.value());
                    }
                    ("retries", OptionValue::Lit(Lit::Int(n))) if options.retries.is_none() => {
                        options.retries = Some(n.base10_parse()?);
                    }
                    ("backoff_secs", OptionValue::Lit(Lit::Float(n)))
                        if options.backoff_secs.is_none() =>
                    {
                        options.backoff_secs = Some(n.base10_parse()?);
                    }
                    ("backoff_secs", OptionValue::Lit(Lit::Int(n)))
                        if options.backoff_secs.is_none() =>
                    {
                        options.backoff_secs = Some(n.base10_parse()?);
                    }
                    ("ordered", OptionValue::None) if options.ordered.is_none() => {
                        options.ordered = Some(true);
                    }
                    ("ordered", OptionValue::Lit(Lit::Bool(b))) if options.ordered.is_none() => {
                        options.ordered = Some(b.value);
                    }
                    _ => return error(arg),
                }
            }
        }
        _ => return error(arg),
    }
    Ok(())
}

#[derive(Clone)]
struct MaybeItemFn {
    attrs: Vec<Attribute>,
    vis: Visibility,
    sig: Signature,
    block: TokenStream2,
}

/// This parses a `TokenStream` into a `MaybeItemFn`
/// (just like `ItemFn`, but skips parsing the body).
impl Parse for MaybeItemFn {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let attrs = input.call(syn::Attribute::parse_outer)?;
        let vis: Visibility = input.parse()?;
        let sig: Signature = input.parse()?;
        let block: TokenStream2 = input.parse()?;
        Ok(Self {
            attrs,
            vis,
            sig,
            block,
        })
    }
}

impl ToTokens for MaybeItemFn {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        tokens.append_all(
            self.attrs
                .iter()
                .filter(|attr| matches!(attr.style, AttrStyle::Outer)),
        );
        self.vis.to_tokens(tokens);
        self.sig.to_tokens(tokens);
        self.block.to_tokens(tokens);
    }
}

/// Marks a function as being a background job.
///
/// The first argument to the function must have type `CurrentJob`.
/// Additional arguments can be used to access context from the job
/// registry. Context is accessed based on the type of the argument.
/// Context arguments must be `Send + Sync + Clone + 'static`.
///
/// The function should be async or return a future.
///
/// The async result must be a `Result<(), E>` type, where `E` is convertible
/// to a `Box<dyn Error + Send + Sync + 'static>`, which is the case for most
/// error types.
///
/// Several options can be provided to the `#[job]` attribute:
///
/// # Name
///
/// ```ignore
/// #[job("example")]
/// #[job(name="example")]
/// ```
///
/// This overrides the name for this job. If unspecified, the fully-qualified
/// name of the function is used. If you move a job to a new module or rename
/// the function, you may which to override the job name to prevent it from
/// changing.
///
/// # Channel name
///
/// ```ignore
/// #[job(channel_name="foo")]
/// ```
///
/// This sets the default channel name on which the job will be spawned.
///
/// # Retries
///
/// ```ignore
/// #[job(retries = 3)]
/// ```
///
/// This sets the default number of retries for the job.
///
/// # Retry backoff
///
/// ```ignore
/// #[job(backoff_secs=1.5)]
/// #[job(backoff_secs=2)]
/// ```
///
/// This sets the default initial retry backoff for the job in seconds.
///
/// # Ordered
///
/// ```ignore
/// #[job(ordered)]
/// #[job(ordered=true)]
/// #[job(ordered=false)]
/// ```
///
/// This sets whether the job will be strictly ordered by default.
///
/// # Prototype
///
/// ```ignore
/// fn my_proto<'a, 'b>(
///     builder: &'a mut JobBuilder<'b>
/// ) -> &'a mut JobBuilder<'b> {
///     builder.set_channel_name("bar")
/// }
///
/// #[job(proto(my_proto))]
/// ```
///
/// This allows setting several job options at once using the specified function,
/// and can be convient if you have several jobs which should have similar
/// defaults.
///
/// # Combinations
///
/// Multiple job options can be combined. The order is not important, but the
/// prototype will always be applied first so that explicit options can override it.
/// Each option can only be provided once in the attribute.
///
/// ```ignore
/// #[job("my_job", proto(my_proto), retries=0, ordered)]
/// ```
///
#[proc_macro_attribute]
pub fn job(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as AttributeArgs);
    let mut inner_fn = parse_macro_input!(item as MaybeItemFn);

    let mut options = JobOptions::default();
    let mut errors = Vec::new();
    for arg in args {
        if let Err(e) = interpret_job_arg(&mut options, arg) {
            errors.push(e.into_compile_error());
        }
    }

    let vis = mem::replace(&mut inner_fn.vis, Visibility::Inherited);
    let name = mem::replace(&mut inner_fn.sig.ident, parse_quote! {inner});
    let fq_name = if let Some(name) = options.name {
        quote! { #name }
    } else {
        let name_str = name.to_string();
        quote! { concat!(module_path!(), "::", #name_str) }
    };

    let mut chain = Vec::new();
    if let Some(proto) = &options.proto {
        chain.push(quote! {
            .set_proto(#proto)
        });
    }
    if let Some(channel_name) = &options.channel_name {
        chain.push(quote! {
            .set_channel_name(#channel_name)
        });
    }
    if let Some(retries) = &options.retries {
        chain.push(quote! {
            .set_retries(#retries)
        });
    }
    if let Some(backoff_secs) = &options.backoff_secs {
        chain.push(quote! {
            .set_retry_backoff(::std::time::Duration::from_secs_f64(#backoff_secs))
        });
    }
    if let Some(ordered) = options.ordered {
        chain.push(quote! {
            .set_ordered(#ordered)
        });
    }

    let extract_ctx: Vec<_> = inner_fn
        .sig
        .inputs
        .iter()
        .skip(1)
        .map(|_| {
            quote! {
                registry.context()
            }
        })
        .collect();

    let expanded = quote! {
        #(#errors)*
        #[allow(non_upper_case_globals)]
        #vis static #name: &'static sqlxmq::NamedJob = &{
            #inner_fn
            sqlxmq::NamedJob::new_internal(
                #fq_name,
                sqlxmq::hidden::BuildFn(|builder| {
                    builder #(#chain)*
                }),
                sqlxmq::hidden::RunFn(|registry, current_job| {
                    registry.spawn_internal(#fq_name, inner(current_job #(, #extract_ctx)*));
                }),
            )
        };
    };
    // Hand the output tokens back to the compiler.
    TokenStream::from(expanded)
}
