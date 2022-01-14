use proc_macro2::TokenStream;

use crate::{Result, Field, Fields, Variant, Struct, Enum, Input};

// used by the macros.
type FnOutput = TokenStream;

pub trait Mapper {
    trait_method!(map_input: Input<'_>, input_default);
    trait_method!(map_struct: Struct<'_>, struct_default);
    trait_method!(map_enum: Enum<'_>, enum_default);
    trait_method!(map_variant: Variant<'_>, variant_default);
    trait_method!(map_fields: Fields<'_>, fields_default);
    trait_method!(map_field: Field<'_>, field_default);
}

impl<M: Mapper + ?Sized> Mapper for &mut M {
    trait_forward!(<M as Mapper>::map_input: Input<'_>);
    trait_forward!(<M as Mapper>::map_struct: Struct<'_>);
    trait_forward!(<M as Mapper>::map_enum: Enum<'_>);
    trait_forward!(<M as Mapper>::map_variant: Variant<'_>);
    trait_forward!(<M as Mapper>::map_fields: Fields<'_>);
    trait_forward!(<M as Mapper>::map_field: Field<'_>);
}

impl Mapper for TokenStream {
    fn map_input(&mut self, _: Input<'_>) -> Result<FnOutput> {
        Ok(self.clone())
    }
}

#[derive(Default)]
pub struct MapperBuild {
    output_mapper: function!(TokenStream),
    input_mapper: function!(Input<'_>),
    struct_mapper: function!(Struct<'_>),
    enum_mapper: function!(Enum<'_>),
    variant_mapper: function!(Variant<'_>),
    fields_mapper: function!(Fields<'_>),
    field_mapper: function!(Field<'_>),
}

impl MapperBuild {
    pub fn new() -> Self {
        MapperBuild::default()
    }

    builder!(with_output: TokenStream, output_mapper);
    try_builder!(try_with_output: TokenStream, output_mapper);

    builder!(input_map: Input<'_>, input_mapper);
    try_builder!(try_input_map: Input<'_>, input_mapper);

    builder!(struct_map: Struct<'_>, struct_mapper);
    try_builder!(try_struct_map: Struct<'_>, struct_mapper);

    builder!(enum_map: Enum<'_>, enum_mapper);
    try_builder!(try_enum_map: Enum<'_>, enum_mapper);

    builder!(variant_map: Variant<'_>, variant_mapper);
    try_builder!(try_variant_map: Variant<'_>, variant_mapper);

    builder!(fields_map: Fields<'_>, fields_mapper);
    try_builder!(try_fields_map: Fields<'_>, fields_mapper);

    builder!(field_map: Field<'_>, field_mapper);
    try_builder!(try_field_map: Field<'_>, field_mapper);
}

impl Mapper for MapperBuild {
    fn map_input(&mut self, value: Input<'_>) -> Result<TokenStream> {
        let output = match self.input_mapper.take() {
            Some(mut m) => {
                let result = m(self, value);
                self.input_mapper = Some(m);
                result?
            }
            None => input_default(&mut *self, value)?
        };

        match self.output_mapper.take() {
            Some(mut m) => {
                let result = m(self, output);
                self.output_mapper = Some(m);
                result
            }
            _ => Ok(output)
        }
    }

    builder_forward!(map_struct: Struct<'_>, struct_mapper, struct_default);
    builder_forward!(map_enum: Enum<'_>, enum_mapper, enum_default);
    builder_forward!(map_variant: Variant<'_>, variant_mapper, variant_default);
    builder_forward!(map_fields: Fields<'_>, fields_mapper, fields_default);
    builder_forward!(map_field: Field<'_>, field_mapper, field_default);
}

pub fn input_default<M: Mapper>(mut mapper: M, value: Input<'_>) -> Result<TokenStream> {
    match value {
        Input::Struct(v) => mapper.map_struct(v),
        Input::Enum(v) => mapper.map_enum(v),
        Input::Union(_) => unimplemented!("union mapping is unimplemented")
    }
}

pub fn enum_default<M: Mapper>(mut mapper: M, value: Enum<'_>) -> Result<TokenStream> {
    let variant = value.variants().map(|v| &v.inner.ident);
    let fields = value.variants().map(|v| v.fields().match_tokens());
    let enum_name = ::std::iter::repeat(value.parent.ident());
    let expression = value.variants()
        .map(|v| mapper.map_variant(v))
        .collect::<Result<Vec<_>>>()?;

    Ok(quote! {
        // FIXME: Check if we can also use id_match_tokens due to match
        // ergonomics. I don't think so, though. If we can't, then ask (in
        // `function`) whether receiver is `&self`, `&mut self` or `self` and
        // bind match accordingly.
        match self {
            #(#enum_name::#variant #fields => { #expression }),*
        }
    })
}

pub fn struct_default<M: Mapper>(mut mapper: M, value: Struct) -> Result<TokenStream> {
    mapper.map_fields(value.fields())
}

pub fn variant_default<M: Mapper>(mut mapper: M, value: Variant) -> Result<TokenStream> {
    mapper.map_fields(value.fields())
}

pub fn fields_null<M: Mapper>(mut mapper: M, value: Fields) -> Result<TokenStream> {
    let field = value.iter()
        .map(|field| mapper.map_field(field))
        .collect::<Result<Vec<_>>>()?;

    Ok(quote!(#(#field)*))
}

pub fn fields_default<M: Mapper>(mut mapper: M, value: Fields) -> Result<TokenStream> {
    let field = value.iter()
        .map(|field| mapper.map_field(field))
        .collect::<Result<Vec<_>>>()?;

    Ok(quote!({ #(#field)* }))
}

pub fn field_default<M: Mapper>(_: M, _: Field) -> Result<TokenStream> {
    Ok(TokenStream::new())
}

pub fn enum_null<M: Mapper>(mut mapper: M, value: Enum<'_>) -> Result<TokenStream> {
    let expression = value.variants()
        .map(|v| mapper.map_variant(v))
        .collect::<Result<Vec<_>>>()?;

    Ok(quote!(#(#expression)*))
}
