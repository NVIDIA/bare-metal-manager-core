#![recursion_limit="256"]

#[macro_use] extern crate quote;
extern crate proc_macro;
extern crate devise_core;

use proc_macro::TokenStream;

use devise_core::*;
use devise_core::ext::SpanDiagnosticExt;

#[derive(Default)]
struct Naked(bool);

impl FromMeta for Naked {
    fn from_meta(meta: &MetaItem) -> Result<Naked> {
        if let Some(meta) = meta.list()?.next() {
            if meta.path()?.is_ident("naked") {
                return Ok(Naked(true));
            }
        }

        Err(meta.span().error("expected `naked`"))
    }
}

#[proc_macro_derive(FromMeta, attributes(meta))]
pub fn derive_from_meta(input: TokenStream) -> TokenStream {
    DeriveGenerator::build_for(input, quote!(impl ::devise::FromMeta))
        .support(Support::NamedStruct)
        .inner_mapper(MapperBuild::new()
            .with_output(|_, output| quote! {
                fn from_meta(
                    __meta: &::devise::MetaItem
                ) -> ::devise::Result<Self> {
                    #[allow(unused_imports)]
                    use ::devise::ext::SpanDiagnosticExt;

                    #output
                }
            })
            .try_fields_map(|_, fields| {
                let naked = |field: &Field| -> bool {
                    Naked::one_from_attrs("meta", &field.attrs)
                        .unwrap()
                        .unwrap_or_default()
                        .0
                };

                // We do this just to emit errors.
                for field in fields.iter() {
                    Naked::one_from_attrs("meta", &field.attrs)?;
                }

                let constructors = fields.iter().map(|f| {
                    let (ident, span) = (f.ident.as_ref().unwrap(), f.span().into());
                    quote_spanned!(span => #[allow(unused_assignments)] let mut #ident = None;)
                });

                let naked_matchers = fields.iter().filter(naked).map(|f| {
                    let (ident, span) = (f.ident.as_ref().unwrap(), f.span().into());
                    let (name, ty) = (ident.to_string(), &f.ty);

                    quote_spanned! { span =>
                        match __list.next() {
                            Some(__i) if __i.is_bare() => {
                                #ident = Some(<#ty>::from_meta(__i)?)
                            },
                            Some(__i) => return Err(__i.span().error(
                                "unexpected keyed parameter: expected literal or identifier")),
                            None => return Err(__span.error(
                                format!("missing expected parameter: `{}`", #name))),
                        };
                    }
                });

                let named_matchers = fields.iter().filter(|f| !naked(f)).map(|f| {
                    let (ident, span) = (f.ident.as_ref().unwrap(), f.span().into());
                    let (name, ty) = (ident.to_string(), &f.ty);

                    quote_spanned! { span =>
                        if __name == #name {
                            if #ident.is_some() {
                                return Err(__span.error(
                                    format!("duplicate attribute parameter: {}", #name)));
                            }

                            #ident = Some(<#ty>::from_meta(__meta)?);
                            continue;
                        }
                    }
                });

                let builders = fields.iter().map(|f| {
                    let (ident, span) = (f.ident.as_ref().unwrap(), f.span().into());
                    let name = ident.to_string();

                    quote_spanned! { span =>
                        #ident: #ident.or_else(::devise::FromMeta::default)
                        .ok_or_else(|| __span.error(
                            format!("missing required attribute parameter: `{}`", #name)))?,
                    }
                });

                Ok(quote! {
                    use ::devise::Spanned;

                    // First, check that the attribute is a list: name(list, ..) and
                    // generate __list: iterator over the items in the attribute.
                    let __span = __meta.span();
                    let mut __list = __meta.list()?;

                    // Set up the constructors for all the variables.
                    #(#constructors)*

                    // Then, parse all of the naked meta items.
                    #(#naked_matchers)*

                    // Parse the rest as non-naked meta items.
                    for __meta in __list {
                        let __span = __meta.span();
                        let __name = match __meta.name() {
                            Some(__ident) => __ident,
                            None => return Err(__span.error("expected key/value `key = value`")),
                        };

                        #(#named_matchers)*

                        let __msg = format!("unexpected attribute parameter: `{}`", __name);
                        return Err(__span.error(__msg));
                    }

                    // Finally, build up the structure.
                    Ok(Self { #(#builders)* })
                })
            })
        )
        .to_tokens()
}
