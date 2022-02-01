use crate::input::{Show, Length};

pub trait Token<I: Input>: Show + PartialEq<I::Token> { }

pub trait Slice<I: Input>: Show + Length + PartialEq<I::Slice> { }

impl<I: Input, T> Token<I> for T where T: Show + PartialEq<I::Token> { }

impl<I: Input, S> Slice<I> for S where S: Show + Length + PartialEq<I::Slice> { }

#[derive(Debug, Copy, Clone)]
pub struct ParserInfo {
    pub name: &'static str,
    pub raw: bool,
}

pub trait Rewind: Sized + Input {
    /// Resets `self` to the position identified by `marker`.
    fn rewind_to(&mut self, marker: Self::Marker);
}

pub trait Input: Sized {
    type Token: Token<Self>;
    type Slice: Slice<Self>;
    type Many: Length;

    type Marker: Copy;
    type Context: Show;

    /// Returns a copy of the current token, if there is one.
    fn token(&mut self) -> Option<Self::Token>;

    /// Returns a copy of the current slice of size `n`, if there is one.
    fn slice(&mut self, n: usize) -> Option<Self::Slice>;

    /// Checks if the current token fulfills `cond`.
    fn peek<F>(&mut self, cond: F) -> bool
        where F: FnMut(&Self::Token) -> bool;

    /// Checks if the current slice of size `n` (if any) fulfills `cond`.
    fn peek_slice<F>(&mut self, n: usize, cond: F) -> bool
        where F: FnMut(&Self::Slice) -> bool;

    /// Checks if the current token fulfills `cond`. If so, the token is
    /// consumed and returned. Otherwise, returns `None`.
    fn eat<F>(&mut self, cond: F) -> Option<Self::Token>
        where F: FnMut(&Self::Token) -> bool;

    /// Checks if the current slice of size `n` (if any) fulfills `cond`. If so,
    /// the slice is consumed and returned. Otherwise, returns `None`.
    fn eat_slice<F>(&mut self, n: usize, cond: F) -> Option<Self::Slice>
        where F: FnMut(&Self::Slice) -> bool;

    /// Takes tokens while `cond` returns true, collecting them into a
    /// `Self::Many` and returning it.
    fn take<F>(&mut self, cond: F) -> Self::Many
        where F: FnMut(&Self::Token) -> bool;

    /// Skips tokens while `cond` returns true. Returns the number of skipped
    /// tokens.
    fn skip<F>(&mut self, cond: F) -> usize
        where F: FnMut(&Self::Token) -> bool;

    /// Returns `true` if there are at least `n` tokens remaining.
    fn has(&mut self, n: usize) -> bool;

    /// Emits a marker that represents the current parse position.
    #[allow(unused_variables)]
    fn mark(&mut self, info: &ParserInfo) -> Self::Marker;

    /// Returns a context to identify the input spanning from `mark` until but
    /// excluding the current position.
    fn context(&mut self, _mark: Self::Marker) -> Self::Context;
}
