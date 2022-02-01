use proc_macro2::TokenStream;
use syn::parse::{Parse, ParseStream, discouraged::Speculative};

enum Input {
    Type(syn::Type),
    Tokens(TokenStream)
}

struct Invocation {
    ty_stream_ty: syn::Path,
    stream_mac: syn::Path,
    stream_trait: syn::Path,
    input: Input,
}

impl Parse for Invocation {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let ty_stream_ty = input.parse()?;
        input.parse::<syn::Token![,]>()?;

        let stream_mac = input.parse()?;
        input.parse::<syn::Token![,]>()?;

        let stream_trait = input.parse()?;
        input.parse::<syn::Token![,]>()?;

        let fork = input.fork();
        let input = match fork.parse() {
            Ok(ty) => {
                input.advance_to(&fork);
                Input::Type(ty)
            }
            Err(_) => Input::Tokens(input.parse()?)
        };

        Ok(Invocation { ty_stream_ty, stream_mac, stream_trait, input })
    }
}

/// This macro exists because we want to disambiguate between input of a type
/// and input of an expression that looks like a type. `macro_rules` matches
/// eagerly on a single token, so something like `foo!(for x in 0..10 {})` will
/// match a `($ty)` branch as will anything that starts with a path.
pub fn _macro(input: proc_macro::TokenStream) -> devise::Result<TokenStream> {
    let i: Invocation = syn::parse(input)?;
    let (s_ty, mac, s_trait) = (i.ty_stream_ty, i.stream_mac, i.stream_trait);
    let tokens = match i.input {
        Input::Tokens(tt) => quote!(#s_ty::from(#mac!(#tt))),
        Input::Type(ty) => quote!(#s_ty<impl #s_trait<Item = #ty>>),
    };

    Ok(tokens)
}
