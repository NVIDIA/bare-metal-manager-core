pub use proc_macro2_diagnostics::SpanDiagnosticExt;

use syn::{*, spanned::Spanned, punctuated::Punctuated, token::Comma};
use proc_macro2::{Span, TokenStream};
use crate::Result;

type TypeParamBounds = Punctuated<TypeParamBound, Token![+]>;

type WherePredicates = Punctuated<WherePredicate, Token![,]>;

pub trait PathExt {
    fn is(&self, global: bool, segments: &[&str]) -> bool;
    fn is_local(&self, segments: &[&str]) -> bool;
    fn is_global(&self, segments: &[&str]) -> bool;
    fn last_ident(&self) -> Option<&Ident>;
    fn generics(&self) -> Option<&Punctuated<GenericArgument, Comma>>;
}

pub trait TypeExt {
    fn strip_lifetimes(&mut self);
    fn with_stripped_lifetimes(&self) -> Type;
    fn replace_lifetimes(&mut self, with: Lifetime);
    fn with_replaced_lifetimes(&self, with: Lifetime) -> Type;
}

pub trait GenericsExt {
    fn add_type_bound(&mut self, bounds: TypeParamBound);
    fn add_type_bounds(&mut self, bounds: TypeParamBounds);
    fn replace(&mut self, ident: &Ident, with: &Ident);
    fn replace_lifetime(&mut self, n: usize, with: &Lifetime) -> bool;
    fn insert_lifetime(&mut self, lifetime: LifetimeDef);

    fn bounded_types(&self, bounds: TypeParamBounds) -> WherePredicates;
    fn parsed_bounded_types(&self, bounds: TokenStream) -> Result<WherePredicates>;
    fn add_where_predicates(&mut self, predicates: WherePredicates);
}

pub trait AstItemExt {
    fn respanned(&self, span: proc_macro2::Span) -> Self where Self: parse::Parse;
    fn respanned_tokens(&self, span: proc_macro2::Span) -> TokenStream;
}

#[macro_export]
macro_rules! quote_respanned {
    ($span:expr => $($t:tt)*) => ({
        use $crate::ext::AstItemExt;
        let tokens = quote_spanned!($span => $($t)*);
        tokens.respanned_tokens($span)
    })
}

pub use quote_respanned;

impl<T: quote::ToTokens> AstItemExt for T {
    fn respanned(&self, span: Span) -> T
        where Self: parse::Parse
    {
        syn::parse2(self.respanned_tokens(span)).unwrap()
    }

    fn respanned_tokens(&self, span: Span) -> TokenStream {
        self.to_token_stream()
            .into_iter()
            .map(|mut token| { token.set_span(span); token })
            .collect()
    }
}

impl GenericsExt for Generics {
    fn add_type_bound(&mut self, bound: TypeParamBound) {
        self.add_type_bounds(Some(bound).into_iter().collect());
    }

    fn add_type_bounds(&mut self, bounds: TypeParamBounds) {
        self.add_where_predicates(self.bounded_types(bounds))
    }

    fn replace(&mut self, ident: &Ident, with: &Ident) {
        IdentReplacer::new(ident, with).visit_generics_mut(self);
    }

    fn replace_lifetime(&mut self, n: usize, with: &Lifetime) -> bool {
        let lifetime_ident = self.lifetimes().nth(n)
            .map(|l| l.lifetime.ident.clone());

        if let Some(ref ident) = lifetime_ident {
            self.replace(ident, &with.ident);
        }

        lifetime_ident.is_some()
    }

    fn insert_lifetime(&mut self, lifetime: LifetimeDef) {
        self.params.insert(0, lifetime.into());
    }

    fn parsed_bounded_types(&self, bounds: TokenStream) -> Result<WherePredicates> {
        use syn::parse::Parser;
        use quote::ToTokens;

        let tokens = bounds.into_token_stream();
        TypeParamBounds::parse_separated_nonempty.parse2(tokens)
            .map(|bounds| self.bounded_types(bounds))
            .map_err(|e| e.span().error(format!("invalid type param bounds: {}", e)))
    }

    fn bounded_types(&self, bounds: TypeParamBounds) -> WherePredicates {
        self.type_params()
            .map(|ty| {
                let ident = &ty.ident;
                let bounds = bounds.respanned_tokens(ty.span());
                syn::parse2(quote_spanned!(ty.span() => #ident: #bounds))
            })
            .collect::<syn::Result<Vec<WherePredicate>>>()
            .expect("valid where predicates")
            .into_iter()
            .collect()
    }

    fn add_where_predicates(&mut self, predicates: WherePredicates) {
        for p in predicates {
            self.make_where_clause().predicates.push(p);
        }
    }
}

pub trait GenericExt {
    fn kind(&self) -> GenericKind;
}

pub trait GenericParamExt {
    fn ident(&self) -> &Ident;
}

pub trait Split2<A, B>: Sized + Iterator {
    fn split2(self) -> (Vec<A>, Vec<B>);
}

pub trait Split3<A, B, C>: Sized + Iterator {
    fn split3(self) -> (Vec<A>, Vec<B>, Vec<C>);
}

pub trait Split4<A, B, C, D>: Sized + Iterator {
    fn split4(self) -> (Vec<A>, Vec<B>, Vec<C>, Vec<D>);
}

pub trait Split6<A, B, C, D, E, F>: Sized + Iterator {
    fn split6(self) -> (Vec<A>, Vec<B>, Vec<C>, Vec<D>, Vec<E>, Vec<F>);
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum GenericKind { Lifetime, Type, Binding, Const, Constraint }

impl PathExt for Path {
    fn is(&self, global: bool, segments: &[&str]) -> bool {
        if self.leading_colon.is_some() != global || self.segments.len() != segments.len() {
            return false;
        }

        for (segment, wanted) in self.segments.iter().zip(segments.iter()) {
            if segment.ident != wanted {
                return false;
            }
        }

        true
    }

    fn is_local(&self, segments: &[&str]) -> bool {
        self.is(false, segments)
    }

    fn is_global(&self, segments: &[&str]) -> bool {
        self.is(true, segments)
    }

    fn last_ident(&self) -> Option<&Ident> {
        self.segments.last().map(|p| &p.ident)
    }

    fn generics(&self) -> Option<&Punctuated<GenericArgument, Comma>> {
        self.segments.last().and_then(|last| {
            match last.arguments {
                PathArguments::AngleBracketed(ref args) => Some(&args.args),
                _ => None
            }
        })
    }
}

impl<A, B, I: IntoIterator<Item = (A, B)> + Iterator> Split2<A, B> for I {
    fn split2(self) -> (Vec<A>, Vec<B>) {
        let (mut first, mut second) = (vec![], vec![]);
        self.into_iter().for_each(|(a, b)| {
            first.push(a);
            second.push(b);
        });

        (first, second)
    }
}

impl<A, B, C, I: IntoIterator<Item = (A, B, C)> + Iterator> Split3<A, B, C> for I {
    fn split3(self) -> (Vec<A>, Vec<B>, Vec<C>) {
        let (mut first, mut second, mut third) = (vec![], vec![], vec![]);
        self.into_iter().for_each(|(a, b, c)| {
            first.push(a);
            second.push(b);
            third.push(c);
        });

        (first, second, third)
    }
}

impl<A, B, C, D, I: IntoIterator<Item = (A, B, C, D)> + Iterator> Split4<A, B, C, D> for I {
    fn split4(self) -> (Vec<A>, Vec<B>, Vec<C>, Vec<D>) {
        let (mut first, mut second, mut third, mut fourth) = (vec![], vec![], vec![], vec![]);
        self.into_iter().for_each(|(a, b, c, d)| {
            first.push(a);
            second.push(b);
            third.push(c);
            fourth.push(d);
        });

        (first, second, third, fourth)
    }
}

impl<A, B, C, D, E, F, I: IntoIterator<Item = (A, B, C, D, E, F)> + Iterator> Split6<A, B, C, D, E, F> for I {
    fn split6(self) -> (Vec<A>, Vec<B>, Vec<C>, Vec<D>, Vec<E>, Vec<F>) {
        let (mut v1, mut v2, mut v3, mut v4, mut v5, mut v6)
            = (vec![], vec![], vec![], vec![], vec![], vec![]);

        self.into_iter().for_each(|(a, b, c, d, e, f)| {
            v1.push(a); v2.push(b); v3.push(c); v4.push(d); v5.push(e); v6.push(f);
        });

        (v1, v2, v3, v4, v5, v6)
    }
}

impl TypeExt for Type {
    fn replace_lifetimes(&mut self, with: Lifetime) {
        let mut r = LifetimeReplacer { with };
        r.visit_type_mut(self);
    }

    fn strip_lifetimes(&mut self) {
        self.replace_lifetimes(syn::parse_quote!('_));
    }

    fn with_stripped_lifetimes(&self) -> Type {
        let mut new = self.clone();
        new.strip_lifetimes();
        new
    }

    fn with_replaced_lifetimes(&self, with: Lifetime) -> Type {
        let mut new = self.clone();
        new.replace_lifetimes(with);
        new
    }
}

pub struct LifetimeReplacer {
    pub with: Lifetime,
}

impl VisitMut for LifetimeReplacer {
    fn visit_lifetime_mut(&mut self, i: &mut Lifetime) {
        let mut ident = self.with.ident.clone();
        ident.set_span(i.ident.span());
        i.ident = ident;
    }
}

impl GenericExt for GenericArgument {
    fn kind(&self) -> GenericKind {
        match *self {
            GenericArgument::Lifetime(..) => GenericKind::Lifetime,
            GenericArgument::Type(..) => GenericKind::Type,
            GenericArgument::Binding(..) => GenericKind::Binding,
            GenericArgument::Constraint(..) => GenericKind::Constraint,
            GenericArgument::Const(..) => GenericKind::Const,
        }
    }
}

impl GenericExt for GenericParam {
    fn kind(&self) -> GenericKind {
        match *self {
            GenericParam::Lifetime(..) => GenericKind::Lifetime,
            GenericParam::Type(..) => GenericKind::Type,
            GenericParam::Const(..) => GenericKind::Const,
        }
    }
}

impl GenericParamExt for GenericParam {
    fn ident(&self) -> &Ident {
        match self {
            &GenericParam::Type(ref ty) => &ty.ident,
            &GenericParam::Lifetime(ref l) => &l.lifetime.ident,
            &GenericParam::Const(ref c) => &c.ident,
        }
    }
}

use syn::visit_mut::VisitMut;

pub struct IdentReplacer<'a> {
    pub to_replace: &'a Ident,
    pub with: &'a Ident,
    pub replaced: bool
}

impl<'a> IdentReplacer<'a> {
    pub fn new(to_replace: &'a Ident, with: &'a Ident) -> Self {
        IdentReplacer { to_replace, with, replaced: false }
    }
}

impl<'a> VisitMut for IdentReplacer<'a> {
    fn visit_ident_mut(&mut self, i: &mut Ident) {
        if i == self.to_replace {
            *i = self.with.clone();
            self.replaced = true;
        }

        visit_mut::visit_ident_mut(self, i);
    }
}
