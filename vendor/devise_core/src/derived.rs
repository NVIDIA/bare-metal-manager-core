use std::ops::Deref;

use syn::{self, DeriveInput};
use quote::ToTokens;

use proc_macro2::TokenStream;
use field::{Field, Fields, FieldsKind};

#[derive(Debug, Clone)]
pub enum ItemInput {
    Struct(syn::ItemStruct),
    Enum(syn::ItemEnum),
    Union(syn::ItemUnion),
}

impl From<DeriveInput> for ItemInput {
    fn from(input: DeriveInput) -> Self {
        match input.data {
            syn::Data::Struct(v) => {
                ItemInput::Struct(syn::ItemStruct {
                    attrs: input.attrs,
                    vis: input.vis,
                    struct_token: v.struct_token,
                    ident: input.ident,
                    generics: input.generics,
                    fields: v.fields,
                    semi_token: v.semi_token,
                })
            }
            syn::Data::Enum(v) => {
                ItemInput::Enum(syn::ItemEnum {
                    attrs: input.attrs,
                    vis: input.vis,
                    enum_token: v.enum_token,
                    ident: input.ident,
                    generics: input.generics,
                    brace_token: v.brace_token,
                    variants: v.variants,
                })
            }
            syn::Data::Union(v) => {
                ItemInput::Union(syn::ItemUnion {
                    attrs: input.attrs,
                    vis: input.vis,
                    ident: input.ident,
                    generics: input.generics,
                    union_token: v.union_token,
                    fields: v.fields,
                })
            }
        }
    }
}

macro_rules! getter {
    ($name:ident -> [$($kind:tt)*] $field:ident $T:ty) => (
        pub fn $name($($kind)* self) -> $T {
            match self {
                ItemInput::Struct(v) => $($kind)* v.$field,
                ItemInput::Enum(v) => $($kind)* v.$field,
                ItemInput::Union(v) => $($kind)* v.$field,
            }
        }
    )
}

impl ItemInput {
    getter!(attrs -> [&] attrs &[syn::Attribute]);
    getter!(attrs_mut -> [&mut] attrs &mut Vec<syn::Attribute>);
    getter!(vis -> [&] vis &syn::Visibility);
    getter!(vis_mut -> [&mut] vis &mut syn::Visibility);
    getter!(ident -> [&] ident &syn::Ident);
    getter!(ident_mut -> [&mut] ident &mut syn::Ident);
    getter!(generics -> [&] generics &syn::Generics);
    getter!(generics_mut -> [&mut] generics &mut syn::Generics);
}

impl ToTokens for ItemInput {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            ItemInput::Struct(v) => v.to_tokens(tokens),
            ItemInput::Enum(v) => v.to_tokens(tokens),
            ItemInput::Union(v) => v.to_tokens(tokens),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Input<'v> {
    Struct(Struct<'v>),
    Enum(Enum<'v>),
    Union(Union<'v>)
}

impl<'v> From<&'v ItemInput> for Input<'v> {
    fn from(input: &'v ItemInput) -> Self {
        match input {
            ItemInput::Struct(v) => Input::Struct(Derived::from(&v, input)),
            ItemInput::Enum(v) => Input::Enum(Derived::from(&v, input)),
            ItemInput::Union(v) => Input::Union(Derived::from(&v, input)),
        }
    }
}

impl ToTokens for Input<'_> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Input::Struct(v) => v.parent.to_tokens(tokens),
            Input::Enum(v) => v.parent.to_tokens(tokens),
            Input::Union(v) => v.parent.to_tokens(tokens),
        }
    }
}

impl Deref for Input<'_> {
    type Target = ItemInput;

    fn deref(&self) -> &Self::Target {
        match self {
            Input::Struct(v) => v.parent,
            Input::Enum(v) => v.parent,
            Input::Union(v) => v.parent,
        }
    }
}

#[derive(Debug)]
pub struct Derived<'p, T, P = &'p ItemInput> {
    pub parent: P,
    pub inner: &'p T,
}

pub type Variant<'v> = Derived<'v, syn::Variant, Enum<'v>>;

pub type Struct<'v> = Derived<'v, syn::ItemStruct>;

pub type Enum<'v> = Derived<'v, syn::ItemEnum>;

pub type Union<'v> = Derived<'v, syn::ItemUnion>;

impl<'p, T, P> Derived<'p, T, P> {
    pub fn from(value: &'p T, parent: P) -> Self {
        Derived { parent, inner: value }
    }
}

impl<'p, T, P> Deref for Derived<'p, T, P> {
    type Target = T;

    fn deref(&self) -> &T {
        self.inner
    }
}

impl<'p, T: ToTokens, P> ToTokens for Derived<'p, T, P> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.inner.to_tokens(tokens)
    }
}

impl<'p, T, P: Copy> Copy for Derived<'p, T, P> { }

impl<'p, T, P: Clone> Clone for Derived<'p, T, P> {
    fn clone(&self) -> Self {
        Self { parent: self.parent.clone(), inner: self.inner, }
    }
}

impl<'f> Variant<'f> {
    pub fn builder<F: Fn(Field) -> TokenStream>(&self, f: F) -> TokenStream {
        let variant = &self.ident;
        let expression = self.fields().iter().map(f);
        let enum_name = &self.parent.ident;
        match self.fields().kind {
            FieldsKind::Named(..) => {
                let field_name = self.fields.iter()
                    .map(|f| f.ident.as_ref().unwrap());
                quote! {
                    #enum_name::#variant { #(#field_name: #expression),* }
                }
            },
            FieldsKind::Unnamed(..) => {
                quote!( #enum_name::#variant(#(#expression),*) )
            }
            FieldsKind::Unit => quote!(#enum_name::#variant),
        }
    }

    pub fn fields(self) -> Fields<'f> {
        self.into()
    }
}

impl<'p> Enum<'p> {
    pub fn variants(self) -> impl Iterator<Item = Variant<'p>> + Clone {
        self.inner.variants.iter()
            .map(move |v| Derived::from(v, self))
    }
}

impl<'p> Struct<'p> {
    pub fn fields(self) -> Fields<'p> {
        self.into()
    }

    pub fn builder<F: Fn(Field) -> TokenStream>(&self, f: F) -> TokenStream {
        let expression = self.fields().iter().map(f);
        let struct_name = &self.parent.ident();
        match self.fields().kind {
            FieldsKind::Named(..) => {
                let field_name = self.fields.iter()
                    .map(|f| f.ident.as_ref().unwrap());

                quote!(#struct_name { #(#field_name: #expression),* })
            },
            FieldsKind::Unnamed(..) => {
                quote!(#struct_name ( #(#expression),* ))
            }
            FieldsKind::Unit => quote!(#struct_name),
        }
    }
}
