mod meta_item;

use syn::parse::Parse;
use syn::{self, Lit::*, spanned::Spanned};
use proc_macro2_diagnostics::SpanDiagnosticExt;
use proc_macro2::{Span, TokenStream};

use generator::Result;

pub use self::meta_item::MetaItem;

// Spans of k/v pair, key, then value.
#[derive(Copy, Clone)]
pub struct SpanWrapped<T> {
    pub span: Span,
    pub key_span: Option<Span>,
    pub full_span: Span,
    pub value: T,
}

pub trait FromMeta: Sized {
    fn from_meta(meta: &MetaItem) -> Result<Self>;

    fn from_attr(attr: &syn::Attribute) -> Result<Self> {
        let (path, inner_tokens) = (&attr.path, &attr.tokens);
        let tokens = quote!(#path #inner_tokens);
        Self::from_meta(&syn::parse2(tokens)?)
    }

    fn from_attrs(
        name: &str,
        attrs: &[syn::Attribute]
    ) -> Result<Vec<Self>> {
        let tokens = name.parse()
            .expect(&format!("`{}` contained invalid tokens", name));

        let path = syn::parse(tokens)
            .expect(&format!("`{}` was not a valid path", name));

        let items = attrs.iter()
            .filter(|attr| attr.path == path)
            .map(|attr| Self::from_attr(attr))
            .collect::<Result<Vec<_>>>()?;

        if items.is_empty() {
            if let Some(default) = Self::default() {
                return Ok(vec![default]);
            }
        }

        Ok(items)
    }

    fn one_from_attrs(name: &str, attrs: &[syn::Attribute]) -> Result<Option<Self>> {
        let tokens = name.parse()
            .expect(&format!("`{}` contained invalid tokens", name));

        let path = syn::parse(tokens)
            .expect(&format!("`{}` was not a valid path", name));

        let mut raw_attrs = attrs.iter().filter(|attr| attr.path == path);
        if let Some(attr) = raw_attrs.nth(1) {
            let msg = format!("duplicate invocation of `{}` attribute", name);
            return Err(attr.span().error(msg));
        }

        Ok(Self::from_attrs(name, attrs)?.pop())
    }

    fn default() -> Option<Self> {
        None
    }
}

impl FromMeta for isize {
    fn from_meta(meta: &MetaItem) -> Result<Self> {
        if let Int(i) = meta.lit()? {
            if let Ok(v) = i.base10_parse::<isize>() {
                return Ok(v);
            }

            return Err(meta.value_span().error("value is out of range for `isize`"));
        }

        Err(meta.value_span().error("invalid value: expected integer literal"))
    }
}

impl FromMeta for usize {
    fn from_meta(meta: &MetaItem) -> Result<Self> {
        if let Int(i) = meta.lit()? {
            if let Ok(v) = i.base10_parse::<usize>() {
                return Ok(v);
            }

            return Err(meta.value_span().error("value is out of range for `usize`"));
        }

        Err(meta.value_span().error("invalid value: expected unsigned integer literal"))
    }
}

impl FromMeta for String {
    fn from_meta(meta: &MetaItem) -> Result<Self> {
        if let Str(s) = meta.lit()? {
            return Ok(s.value());
        }

        Err(meta.value_span().error("invalid value: expected string literal"))
    }
}

impl FromMeta for bool {
    fn from_meta(meta: &MetaItem) -> Result<Self> {
        if let MetaItem::Path(_) = meta {
            return Ok(true);
        }

        if let Bool(b) = meta.lit()? {
            return Ok(b.value);
        }

        return Err(meta.value_span().error("invalid value: expected boolean"));
    }
}

impl FromMeta for syn::Expr {
    fn from_meta(meta: &MetaItem) -> Result<Self> {
        meta.expr().map(|v| v.clone())
    }
}

impl<T: FromMeta> FromMeta for Option<T> {
    fn from_meta(meta: &MetaItem) -> Result<Self> {
        T::from_meta(meta).map(Some)
    }

    fn default() -> Option<Self> {
        Some(None)
    }
}

impl<T: Parse, P: Parse> FromMeta for syn::punctuated::Punctuated<T, P> {
    fn from_meta(meta: &MetaItem) -> Result<Self> {
        meta.parse_value_with(Self::parse_terminated, "punctuated list")
    }
}

impl<T: FromMeta> FromMeta for SpanWrapped<T> {
    fn from_meta(meta: &MetaItem) -> Result<Self> {
        let span = meta.value_span();
        let key_span = meta.attr_path().map(|i| i.span());
        let full_span = meta.span();
        T::from_meta(meta).map(|value| SpanWrapped { full_span, key_span, span, value })
    }
}

impl FromMeta for TokenStream {
    fn from_meta(meta: &MetaItem) -> Result<Self> {
        meta.parse_value("token stream")
    }
}

impl<T: ::quote::ToTokens> ::quote::ToTokens for SpanWrapped<T> {
    fn to_tokens(&self, tokens: &mut ::proc_macro2::TokenStream) {
        self.value.to_tokens(tokens)
    }
}

use std::ops::{Deref, DerefMut};

impl<T> Deref for SpanWrapped<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> DerefMut for SpanWrapped<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

use std::fmt;

impl<T: fmt::Debug> fmt::Debug for SpanWrapped<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SpanWrapped")
            .field(&self.value)
            .finish()
    }
}
