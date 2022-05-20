//! DSL implementation for defining finite state machines for `rust-fsm`. See
//! more in the `rust-fsm` crate documentation.

#![recursion_limit = "128"]
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use std::collections::BTreeSet;
use syn::{parse_macro_input, Ident};

mod parser;

/// The full information about a state transition. Used to unify the
/// represantion of the simple and the compact forms.
struct Transition<'a> {
    initial_state: &'a Ident,
    input_value: &'a Ident,
    final_state: &'a Ident,
    output: &'a Option<Ident>,
}

#[proc_macro]
/// Produce a state machine definition from the provided `rust-fmt` DSL
/// description.
pub fn state_machine(tokens: TokenStream) -> TokenStream {
    let input = parse_macro_input!(tokens as parser::StateMachineDef);

    let derives = if let Some(derives) = input.derives {
        quote! { #[derive(#(#derives,)*)] }
    } else {
        quote! {}
    };

    if input.transitions.is_empty() {
        let output = quote! {
            compile_error!("rust-fsm: at least one state transition must be provided");
        };
        return output.into();
    }

    let struct_name = input.name;
    let visibility = input.visibility;

    let transitions: Vec<_> = input
        .transitions
        .iter()
        .flat_map(|def| {
            def.transitions.iter().map(move |transition| Transition {
                initial_state: &def.initial_state,
                input_value: &transition.input_value,
                final_state: &transition.final_state,
                output: &transition.output,
            })
        })
        .collect();

    let mut states = BTreeSet::new();
    let mut inputs = BTreeSet::new();
    let mut outputs = BTreeSet::new();

    states.insert(&input.initial_state);

    for transition in transitions.iter() {
        states.insert(&transition.initial_state);
        states.insert(&transition.final_state);
        inputs.insert(&transition.input_value);
        if let Some(ref output) = transition.output {
            outputs.insert(output);
        }
    }

    let states_enum_name = Ident::new(&format!("{}State", struct_name), struct_name.span());
    let initial_state_name = &input.initial_state;

    let inputs_enum_name = Ident::new(&format!("{}Input", struct_name), struct_name.span());

    let mut transition_cases = vec![];
    for transition in transitions.iter() {
        let initial_state = &transition.initial_state;
        let input_value = &transition.input_value;
        let final_state = &transition.final_state;
        transition_cases.push(quote! {
            (#states_enum_name::#initial_state, #inputs_enum_name::#input_value) => {
                Some(#states_enum_name::#final_state)
            }
        });
    }

    let (outputs_repr, outputs_type, output_impl) = if !outputs.is_empty() {
        let outputs_type_name = Ident::new(&format!("{}Output", struct_name), struct_name.span());
        let outputs_repr = quote! {
            #derives
            #visibility enum #outputs_type_name {
                #(#outputs),*
            }
        };

        let outputs_type = quote! { #outputs_type_name };

        let mut output_cases = vec![];
        for transition in transitions.iter() {
            if let Some(output_value) = &transition.output {
                let initial_state = &transition.initial_state;
                let input_value = &transition.input_value;
                output_cases.push(quote! {
                    (#states_enum_name::#initial_state, #inputs_enum_name::#input_value) => {
                        Some(#outputs_type_name::#output_value)
                    }
                });
            }
        }

        let output_impl = quote! {
            match (state, input) {
                #(#output_cases)*
                _ => None,
            }
        };

        (outputs_repr, outputs_type, output_impl)
    } else {
        (quote! {}, quote! { () }, quote! {None})
    };

    let output = quote! {
        #derives
        #visibility struct #struct_name;

        #derives
        #visibility enum #states_enum_name {
            #(#states),*
        }

        #derives
        #visibility enum #inputs_enum_name {
            #(#inputs),*
        }

        #outputs_repr

        impl rust_fsm::StateMachineImpl for #struct_name {
            type Input = #inputs_enum_name;
            type State = #states_enum_name;
            type Output = #outputs_type;
            const INITIAL_STATE: Self::State = #states_enum_name::#initial_state_name;

            fn transition(state: &Self::State, input: &Self::Input) -> Option<Self::State> {
                match (state, input) {
                    #(#transition_cases)*
                    _ => None,
                }
            }

            fn output(state: &Self::State, input: &Self::Input) -> Option<Self::Output> {
                #output_impl
            }
        }
    };

    output.into()
}
