use std::ops::Deref;

use proc_macro2::TokenStream;
use syn::{self, Token, punctuated::Punctuated, spanned::Spanned, parse::Parser};
use proc_macro2_diagnostics::{SpanDiagnosticExt, Diagnostic};
use quote::ToTokens;

use crate::ext::{GenericExt, GenericParamExt, GenericsExt};
use crate::support::Support;
use crate::derived::{ItemInput, Input};
use crate::mapper::Mapper;
use crate::validator::Validator;

pub type Result<T> = std::result::Result<T, Diagnostic>;

pub struct TraitItem {
    item: syn::ItemImpl,
    pub path: syn::Path,
    pub name: syn::Ident,
}

impl TraitItem {
    fn parse<T: ToTokens>(raw: T) -> Self {
        let item: syn::ItemImpl = syn::parse2(quote!(#raw for Foo {}))
            .expect("invalid impl token stream");

        let path = item.trait_.clone()
            .expect("impl does not have trait")
            .1;

        let name = path.segments.last()
            .map(|s| s.ident.clone())
            .expect("trait to impl for is empty");

        Self { item, path, name }
    }
}

impl Deref for TraitItem {
    type Target = syn::ItemImpl;

    fn deref(&self) -> &Self::Target {
        &self.item
    }
}

pub struct DeriveGenerator {
    pub input: ItemInput,
    pub item: TraitItem,
    pub support: Support,
    pub validator: Option<Box<dyn Validator>>,
    pub inner_mappers: Vec<Box<dyn Mapper>>,
    pub outer_mappers: Vec<Box<dyn Mapper>>,
    pub type_bound_mapper: Option<Box<dyn Mapper>>,
    generic_replacements: Vec<(usize, usize)>,
}

impl DeriveGenerator {
    pub fn build_for<I, T>(input: I, trait_impl: T) -> DeriveGenerator
        where I: Into<TokenStream>, T: ToTokens
    {
        let item = TraitItem::parse(trait_impl);
        let input: syn::DeriveInput = syn::parse2(input.into())
            .expect("invalid derive input");

        DeriveGenerator {
            item,
            input: input.into(),
            support: Support::default(),
            generic_replacements: vec![],
            validator: None,
            type_bound_mapper: None,
            inner_mappers: vec![],
            outer_mappers: vec![],
        }
    }

    pub fn support(&mut self, support: Support) -> &mut Self {
        self.support = support;
        self
    }

    pub fn type_bound<B: ToTokens>(&mut self, bound: B) -> &mut Self {
        let tokens = bound.to_token_stream();
        self.type_bound_mapper(crate::MapperBuild::new()
            .try_input_map(move |_, input| {
                let tokens = tokens.clone();
                let bounds = input.generics().parsed_bounded_types(tokens)?;
                Ok(bounds.into_token_stream())
            }))
    }

    /// Take the 0-indexed `trait_gen`th generic in the generics in impl<..>
    /// being built and substitute those tokens in place of the 0-indexed
    /// `impl_gen`th generic of the same kind in the input type.
    pub fn replace_generic(&mut self, trait_gen: usize, impl_gen: usize) -> &mut Self {
        self.generic_replacements.push((trait_gen, impl_gen));
        self
    }

    pub fn validator<V: Validator + 'static>(&mut self, validator: V) -> &mut Self {
        self.validator = Some(Box::new(validator));
        self
    }

    pub fn type_bound_mapper<V: Mapper + 'static>(&mut self, mapper: V) -> &mut Self {
        self.type_bound_mapper = Some(Box::new(mapper));
        self
    }

    pub fn inner_mapper<V: Mapper + 'static>(&mut self, mapper: V) -> &mut Self {
        self.inner_mappers.push(Box::new(mapper));
        self
    }

    pub fn outer_mapper<V: Mapper + 'static>(&mut self, mapper: V) -> &mut Self {
        self.outer_mappers.push(Box::new(mapper));
        self
    }

    fn _to_tokens(&mut self) -> Result<TokenStream> {
        // Step 1: Run all validators.
        // Step 1a: First, check for data support.
        let input = Input::from(&self.input);
        let (span, support) = (input.span(), self.support);
        match input {
            Input::Struct(v) => {
                if v.fields().are_named() && !support.contains(Support::NamedStruct) {
                    return Err(span.error("named structs are not supported"));
                }

                if !v.fields().are_named() && !support.contains(Support::TupleStruct) {
                    return Err(span.error("tuple structs are not supported"));
                }
            }
            Input::Enum(..) if !support.contains(Support::Enum) => {
                return Err(span.error("enums are not supported"));
            }
            Input::Union(..) if !support.contains(Support::Union) => {
                return Err(span.error("unions are not supported"));
            }
            _ => { /* we're okay! */ }
        }

        // Step 1b: Second, check for generics support.
        for generic in &input.generics().params {
            use syn::GenericParam::*;

            let span = generic.span();
            match generic {
                Type(..) if !support.contains(Support::Type) => {
                    return Err(span.error("type generics are not supported"));
                }
                Lifetime(..) if !support.contains(Support::Lifetime) => {
                    return Err(span.error("lifetime generics are not supported"));
                }
                Const(..) if !support.contains(Support::Const) => {
                    return Err(span.error("const generics are not supported"));
                }
                _ => { /* we're okay! */ }
            }
        }

        // Step 1c: Third, run the custom validator, if any.
        if let Some(validator) = &mut self.validator {
            validator.validate_input((&self.input).into())?;
        }

        // Step 2: Generate the code!

        // Step 2a: Copy user's generics to mutate with bounds + replacements.
        let mut type_generics = self.input.generics().clone();

        // Step 2b: Perform generic replacememnt: replace generics in the input
        // type with generics from the trait definition: 1) determine the
        // identifer of the generic to be replaced in the type. 2) replace every
        // identifer in the type with the same name with the identifer of the
        // replacement trait generic. For example:
        //   * replace: trait_i = 1, type_i = 0
        //   * trait: impl<'_a, '_b: '_a> GenExample<'_a, '_b>
        //   * type: GenFooAB<'x, 'y: 'x>
        //   * new type: GenFooAB<'_b, 'y: 'b>
        for (trait_i, type_i) in &self.generic_replacements {
            let idents = self.item.generics.params.iter()
                .nth(*trait_i)
                .and_then(|trait_gen| type_generics.params.iter()
                    .filter(|gen| gen.kind() == trait_gen.kind())
                    .nth(*type_i)
                    .map(|type_gen| (trait_gen.ident(), type_gen.ident().clone())));

            if let Some((with, ref to_replace)) = idents {
                type_generics.replace(to_replace, with);
            }
        }

        // Step 2c.1: Generate the code for each function.
        let mut function_code = vec![];
        for mapper in &mut self.inner_mappers {
            let tokens = mapper.map_input((&self.input).into())?;
            function_code.push(tokens);
        }

        // Step 2c.2: Generate the code for each item.
        let mut item_code = vec![];
        for mapper in &mut self.outer_mappers {
            let tokens = mapper.map_input((&self.input).into())?;
            item_code.push(tokens);
        }

        // Step 2d: Add the requested type bounds.
        if let Some(ref mut mapper) = self.type_bound_mapper {
            let tokens = mapper.map_input((&self.input).into())?;
            let bounds = Punctuated::<syn::WherePredicate, Token![,]>::parse_terminated
                .parse2(tokens)
                .map_err(|e| e.span().error(format!("invalid type bounds: {}", e)))?;

            type_generics.add_where_predicates(bounds);
        }

        // Step 2e: Determine which generics from the type need to be added to
        // the trait's `impl<>` generics. These are all of the generics in the
        // type that aren't in the trait's `impl<>` already.
        let mut type_generics_for_impl = self.item.generics.clone();
        for type_gen in &type_generics.params {
            let type_gen_in_trait_gens = type_generics_for_impl.params.iter()
                .map(|gen| gen.ident())
                .find(|g| g == &type_gen.ident())
                .is_some();

            if !type_gen_in_trait_gens {
                type_generics_for_impl.params.push(type_gen.clone())
            }
        }

        // Step 2f: Split the generics, but use the `impl_generics` from above.
        let (impl_gen, _, _) = type_generics_for_impl.split_for_impl();
        let (_, ty_gen, where_gen) = type_generics.split_for_impl();

        // Step 2g: Generate the complete implementation.
        let (target, trait_path) = (&self.input.ident(), &self.item.path);
        Ok(quote! {
            #[allow(non_snake_case)]
            const _: () = {
                #(#item_code)*

                impl #impl_gen #trait_path for #target #ty_gen #where_gen {
                    #(#function_code)*
                }
            };
        })
    }

    pub fn debug(&mut self) -> &mut Self {
        match self._to_tokens() {
            Ok(tokens) => println!("Tokens produced: {}", tokens.to_string()),
            Err(e) => println!("Error produced: {:?}", e)
        }

        self
    }

    pub fn to_tokens<T: From<TokenStream>>(&mut self) -> T {
        self.try_to_tokens()
            .unwrap_or_else(|diag| diag.emit_as_item_tokens())
            .into()
    }

    pub fn try_to_tokens<T: From<TokenStream>>(&mut self) -> Result<T> {
        // FIXME: Emit something like: Trait: msg.
        self._to_tokens()
            .map_err(|diag| {
                if let Some(last) = self.item.path.segments.last() {
                    use proc_macro2::Span;
                    use proc_macro2_diagnostics::Level::*;

                    let id = &last.ident;
                    let msg = match diag.level() {
                        Error => format!("error occurred while deriving `{}`", id),
                        Warning => format!("warning issued by `{}` derive", id),
                        Note => format!("note issued by `{}` derive", id),
                        Help => format!("help provided by `{}` derive", id),
                        _ => format!("while deriving `{}`", id)
                    };

                    diag.span_note(Span::call_site(), msg)
                } else {
                    diag
                }
            })
            .map(|t| t.into())
    }
}
