use std::ops::Deref;

use quote::ToTokens;
use proc_macro2::TokenStream;
use syn::{self, Member, Index, punctuated::Punctuated, spanned::Spanned};

use crate::derived::{Derived, Struct, Variant, Union};
use crate::ItemInput;

#[derive(Debug, Copy, Clone)]
pub enum FieldParent<'p> {
    Variant(Variant<'p>),
    Struct(Struct<'p>),
    Union(Union<'p>),
}

impl<'p> FieldParent<'p> {
    pub fn input(&self) -> &ItemInput {
        match self {
            FieldParent::Variant(v) => v.parent.parent,
            FieldParent::Struct(v) => v.parent,
            FieldParent::Union(v) => v.parent,
        }
    }

    pub fn attrs(&self) -> &[syn::Attribute] {
        match self {
            FieldParent::Variant(v) => &v.attrs,
            FieldParent::Struct(_) | FieldParent::Union(_) => self.input().attrs(),
        }
    }
}

impl ToTokens for FieldParent<'_> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            FieldParent::Variant(v) => v.to_tokens(tokens),
            FieldParent::Struct(v) => v.to_tokens(tokens),
            FieldParent::Union(v) => v.to_tokens(tokens),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum FieldsKind<'p> {
    Named(&'p syn::FieldsNamed),
    Unnamed(&'p syn::FieldsUnnamed),
    Unit
}

impl<'a> From<&'a syn::Fields> for FieldsKind<'a> {
    fn from(fields: &'a syn::Fields) -> Self {
        match fields {
            syn::Fields::Named(fs) => FieldsKind::Named(&fs),
            syn::Fields::Unnamed(fs) => FieldsKind::Unnamed(&fs),
            syn::Fields::Unit => FieldsKind::Unit,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Fields<'p> {
    pub parent: FieldParent<'p>,
    pub(crate) kind: FieldsKind<'p>,
}

impl<'p> From<Variant<'p>> for Fields<'p> {
    fn from(v: Variant<'p>) -> Self {
        Fields { parent: FieldParent::Variant(v), kind: (&v.inner.fields).into() }
    }
}

impl<'p> From<Struct<'p>> for Fields<'p> {
    fn from(v: Struct<'p>) -> Self {
        Fields { parent: FieldParent::Struct(v), kind: (&v.inner.fields).into() }
    }
}

impl<'p> From<Union<'p>> for Fields<'p> {
    fn from(v: Union<'p>) -> Self {
        Fields { parent: FieldParent::Union(v), kind: FieldsKind::Named(&v.inner.fields) }
    }
}

impl<'f> Fields<'f> {
    fn fields(&self) -> Option<&'f Punctuated<syn::Field, syn::token::Comma>> {
        match self.kind {
            FieldsKind::Named(i) => Some(&i.named),
            FieldsKind::Unnamed(i) => Some(&i.unnamed),
            FieldsKind::Unit => None
        }
    }

    pub fn iter(self) -> impl Iterator<Item = Field<'f>> + Clone {
        self.fields()
            .into_iter()
            .flat_map(|fields| fields.iter())
            .enumerate()
            .map(move |(index, field)| Field {
                index,
                field: Derived::from(field, self.parent),
            })
    }

    pub fn is_empty(self) -> bool {
        self.count() == 0
    }

    pub fn count(self) -> usize {
        self.fields().map(|f| f.len()).unwrap_or(0)
    }

    pub fn are_named(self) -> bool {
        match self.kind {
            FieldsKind::Named(..) => true,
            _ => false
        }
    }

    pub fn are_unnamed(self) -> bool {
        match self.kind {
            FieldsKind::Unnamed(..) => true,
            _ => false
        }
    }

    pub fn are_unit(self) -> bool {
        match self.kind {
            FieldsKind::Unit => true,
            _ => false
        }
    }

    fn surround(self, tokens: TokenStream) -> TokenStream {
        match self.kind {
            FieldsKind::Named(..) => quote_spanned!(self.span() => { #tokens }),
            FieldsKind::Unnamed(..) => quote_spanned!(self.span() => ( #tokens )),
            FieldsKind::Unit => quote!()
        }
    }

    pub fn match_tokens(self) -> TokenStream {
        // This relies on match ergonomics to work in either case.
        let idents = self.iter().map(|field| {
            let match_ident = field.match_ident();
            match field.ident {
                Some(ref id) => quote!(#id: #match_ident),
                None => quote!(#match_ident)
            }

        });

        self.surround(quote!(#(#idents),*))
    }

    pub fn builder<F: Fn(Field) -> TokenStream>(&self, f: F) -> TokenStream {
        match self.parent {
            FieldParent::Struct(s) => s.builder(f),
            FieldParent::Variant(v) => v.builder(f),
            FieldParent::Union(_) => panic!("unions are not supported")
        }
    }
}

impl<'a> ToTokens for Fields<'a> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self.kind {
            FieldsKind::Named(v) => v.to_tokens(tokens),
            FieldsKind::Unnamed(v) => v.to_tokens(tokens),
            FieldsKind::Unit => tokens.extend(quote_spanned!(self.parent.span() => ()))
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Field<'f> {
    pub field: Derived<'f, syn::Field, FieldParent<'f>>,
    pub index: usize,
}

impl<'f> Field<'f> {
    pub fn match_ident(self) -> syn::Ident {
        let name = match self.ident {
            Some(ref id) => format!("__{}", id),
            None => format!("__{}", self.index)
        };

        syn::Ident::new(&name, self.span().into())
    }

    pub fn accessor(&self) -> TokenStream {
        if let FieldParent::Variant(_) = self.parent {
            let ident = self.match_ident();
            quote!(#ident)
        } else {
            let span = self.field.span().into();
            let member = match self.ident {
                Some(ref ident) => Member::Named(ident.clone()),
                None => Member::Unnamed(Index { index: self.index as u32, span })
            };

            quote_spanned!(span => self.#member)
        }
    }
}

impl<'f> Deref for Field<'f> {
    type Target = Derived<'f, syn::Field, FieldParent<'f>>;

    fn deref(&self) -> &Self::Target {
        &self.field
    }
}

impl<'f> ToTokens for Field<'f> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.field.to_tokens(tokens)
    }
}
