use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::quote_spanned;
use syn::{Expr, ExprLit, Lit};
use syn::spanned::Spanned;

pub trait ReadEnv {
    fn read_env(&self, var_name: &String) -> Option<String>;
}

pub struct RealEnv;

impl ReadEnv for RealEnv {
    fn read_env(&self, var_name: &String) -> Option<String> {
        std::env::var_os(var_name)
            .and_then(|s| s.into_string().ok())
    }
}

pub struct TestEnv {
    env_vars: HashMap<String, String>
}

impl TestEnv {
    pub fn builder() -> TestEnvBuilder {
        TestEnvBuilder {
            env_vars: HashMap::new()
        }
    }
}

impl ReadEnv for TestEnv {
    fn read_env(&self, var_name: &String) -> Option<String> {
        self.env_vars.get(var_name).cloned()
    }
}

pub struct TestEnvBuilder {
    env_vars: HashMap<String, String>
}

impl TestEnvBuilder {
    pub fn set(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(name.into(), value.into());
        self
    }

    pub fn build(self) -> TestEnv {
        TestEnv {
            env_vars: self.env_vars
        }
    }
}

/// Inner implementation details of `const_env::from_env`.
pub fn from_env(attr: TokenStream, item: TokenStream, read_env: impl ReadEnv) -> TokenStream {
    if let Ok(mut item_const) = syn::parse2::<syn::ItemConst>(item.clone()) {
        let default_var_name = format!("{}", item_const.ident);
        let var_name = extract_var_name(attr, default_var_name);
        let var_value = match read_env.read_env(&var_name) {
            Some(val) => val,
            None => return item
        };
        let new_expr = value_to_literal(&var_value, &item_const.expr);
        let span = item_const.span();
        item_const.expr = Box::new(new_expr);
        quote_spanned!(span => #item_const)
    } else if let Ok(mut item_static) = syn::parse2::<syn::ItemStatic>(item.clone()) {
        let default_var_name = format!("{}", item_static.ident);
        let var_name = extract_var_name(attr, default_var_name);
        let var_value = match read_env.read_env(&var_name) {
            Some(val) => val,
            None => return item
        };
        let new_expr = value_to_literal(&var_value, &item_static.expr);
        let span = item_static.span();
        item_static.expr = Box::new(new_expr);
        quote_spanned!(span => #item_static)
    } else {
        panic!("TODO: error reporting");
    }
}

fn extract_var_name(attr: TokenStream, default: String) -> String {
    if attr.is_empty() {
        return default;
    }
    let expr: Expr = syn::parse2(attr)
        .expect("Unable to parse attribute args as expression");
    extract_var_name_from_expr(&expr)
}

fn extract_var_name_from_expr(expr: &Expr) -> String {
    match expr {
        Expr::Lit(literal) => {
            match &literal.lit {
                Lit::Str(lit_str) => {
                    lit_str.value()
                },
                _ => panic!("Attribute arguments are not a valid string literal")
            }
        },
        Expr::Paren(paren) => {
            extract_var_name_from_expr(&paren.expr)
        },
        _ => {
            panic!("Attribute arguments are not a valid string literal expression: {:?}", expr)
        }
    }
}

fn value_to_literal(value: &str, original_expr: &Expr) -> Expr {
    match original_expr {
        Expr::Unary(_) => {
            // A unary sign indicates this is a numeric literal which doesn't need any
            // escaping, so we can parse it directly.
            let new: Expr = syn::parse_str(value)
                .expect("Failed to parse environment variable contents as valid expresion");
            return new;
        },
        Expr::Lit(literal) => {
            let new_lit = match &literal.lit {
                Lit::Str(original) => {
                    let mut new: syn::LitStr = syn::parse_str(&format!("\"{}\"", value))
                        .expect("Failed to parse environment variable contents as literal string");
                    new.set_span(original.span());
                    Lit::Str(new)
                },
                Lit::ByteStr(original) => {
                    let mut new: syn::LitByteStr = syn::parse_str(&format!("b\"{}\"", value))
                        .expect("Failed to parse environment variable contents as literal byte string");
                    new.set_span(original.span());
                    Lit::ByteStr(new)
                },
                Lit::Byte(original) => {
                    let mut new: syn::LitByte = syn::parse_str(&format!("b'{}'", value))
                        .expect("Failed to parse environment variable contents as literal byte");
                    new.set_span(original.span());
                    Lit::Byte(new)
                },
                Lit::Char(original) => {
                    let mut new: syn::LitChar = syn::parse_str(&format!("'{}'", value))
                        .expect("Failed to parse environment variable contents as literal character");
                    new.set_span(original.span());
                    Lit::Char(new)
                },
                // These variants do not need any escaping and can be parsed as an expression
                // directly.
                Lit::Bool(_) | Lit::Int(_) | Lit::Float(_) | Lit::Verbatim(_) => {
                    let new: Expr = syn::parse_str(value)
                        .expect("Failed to parse environment variable contents as valid expression");
                    return new;
                }
            };
            ExprLit {
                attrs: literal.attrs.clone(),
                lit: new_lit
            }.into()
        },
        _ => panic!("Original const expression was not a recognized literal expression")
    }
}