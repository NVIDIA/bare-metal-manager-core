use crate::{Result, Field, Fields, Variant, Struct, Enum, Input};

type FnOutput = ();

pub trait Validator {
    trait_method!(validate_input: Input<'_>, input_default);
    trait_method!(validate_struct: Struct<'_>, struct_default);
    trait_method!(validate_enum: Enum<'_>, enum_default);
    trait_method!(validate_variant: Variant<'_>, variant_default);
    trait_method!(validate_fields: Fields<'_>, fields_default);
    trait_method!(validate_field: Field<'_>, field_default);
}

impl<V: Validator + ?Sized> Validator for &mut V {
    trait_forward!(<V as Validator>::validate_input: Input<'_>);
    trait_forward!(<V as Validator>::validate_struct: Struct<'_>);
    trait_forward!(<V as Validator>::validate_enum: Enum<'_>);
    trait_forward!(<V as Validator>::validate_variant: Variant<'_>);
    trait_forward!(<V as Validator>::validate_fields: Fields<'_>);
    trait_forward!(<V as Validator>::validate_field: Field<'_>);
}

#[derive(Default)]
pub struct ValidatorBuild {
    input_validator: function!(Input<'_>),
    struct_validator: function!(Struct<'_>),
    enum_validator: function!(Enum<'_>),
    variant_validator: function!(Variant<'_>),
    fields_validator: function!(Fields<'_>),
    field_validator: function!(Field<'_>),
}

impl ValidatorBuild {
    pub fn new() -> Self {
        ValidatorBuild::default()
    }

    try_builder!(input_validate: Input<'_>, input_validator);
    try_builder!(struct_validate: Struct<'_>, struct_validator);
    try_builder!(enum_validate: Enum<'_>, enum_validator);
    try_builder!(variant_validate: Variant<'_>, variant_validator);
    try_builder!(fields_validate: Fields<'_>, fields_validator);
    try_builder!(field_validate: Field<'_>, field_validator);
}

impl Validator for ValidatorBuild {
    builder_def_fwd!(validate_input: Input<'_>, input_validator, input_default);
    builder_def_fwd!(validate_struct: Struct<'_>, struct_validator, struct_default);
    builder_def_fwd!(validate_enum: Enum<'_>, enum_validator, enum_default);
    builder_def_fwd!(validate_variant: Variant<'_>, variant_validator, variant_default);
    builder_def_fwd!(validate_fields: Fields<'_>, fields_validator, fields_default);
    builder_def_fwd!(validate_field: Field<'_>, field_validator, field_default);
}

pub fn input_default<V: Validator>(mut validator: V, value: Input<'_>) -> Result<()> {
    match value {
        Input::Struct(v) => validator.validate_struct(v),
        Input::Enum(v) => validator.validate_enum(v),
        Input::Union(_) => unimplemented!("union validation is unimplemented")
    }
}

pub fn enum_default<V: Validator>(mut validator: V, value: Enum) -> Result<()> {
    for v in value.variants() {
        validator.validate_variant(v)?;
    }

    Ok(())
}

pub fn struct_default<V: Validator>(mut validator: V, value: Struct) -> Result<()> {
    validator.validate_fields(value.fields())
}

pub fn variant_default<V: Validator>(mut validator: V, value: Variant) -> Result<()> {
    validator.validate_fields(value.fields())
}

pub fn fields_default<V: Validator>(mut validator: V, value: Fields) -> Result<()> {
    for f in value.iter() {
        validator.validate_field(f)?;
    }

    Ok(())
}

pub fn field_default<V: Validator>(_: V, _: Field) -> Result<()> {
    Ok(())
}
