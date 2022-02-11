use std::iter::FromIterator;

use proc_macro::{Delimiter, Group, Ident, Punct, Spacing, Span, TokenStream, TokenTree};

use crate::{iter::TokenIter, Result};

pub(crate) fn tt_span(tt: Option<&TokenTree>) -> Span {
    tt.map_or_else(Span::call_site, TokenTree::span)
}

pub(crate) fn parse_as_empty(tokens: &mut TokenIter) -> Result<()> {
    match tokens.next() {
        Some(tt) => bail!(tt.span(), "unexpected token: `{}`", tt),
        None => Ok(()),
    }
}

// (`#[cfg(<tokens>)]`, `#[cfg(not(<tokens>))]`)
pub(crate) fn cfg_attrs(tokens: TokenStream) -> (TokenStream, TokenStream) {
    let f = |tokens| {
        let tokens = TokenStream::from_iter(vec![
            TokenTree::Ident(Ident::new("cfg", Span::call_site())),
            TokenTree::Group(Group::new(Delimiter::Parenthesis, tokens)),
        ]);
        TokenStream::from_iter(vec![
            TokenTree::Punct(Punct::new('#', Spacing::Alone)),
            TokenTree::Group(Group::new(Delimiter::Bracket, tokens)),
        ])
    };

    let cfg_not = TokenTree::Group(Group::new(Delimiter::Parenthesis, tokens.clone()));
    let cfg_not = TokenStream::from_iter(vec![
        TokenTree::Ident(Ident::new("not", Span::call_site())),
        cfg_not,
    ]);

    (f(tokens), f(cfg_not))
}
