use std::fmt;

use crate::input::{Input, Rewind, ParserInfo};

pub trait Debugger<I: Input> {
    fn on_entry(&mut self, info: &ParserInfo);
    fn on_exit(&mut self, info: &ParserInfo, ok: bool, ctxt: I::Context);
}

pub struct Options<I> {
    pub stacked_context: bool,
    pub debugger: Option<Box<dyn Debugger<I>>>,
}

impl<I> fmt::Debug for Options<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
            .field("stacked_context", &self.stacked_context)
            .field("debugger", &self.debugger.is_some())
            .finish()
    }
}

impl<I: Input> Default for Options<I> {
    #[cfg(debug_assertions)]
    fn default() -> Self {
        use crate::debug::TreeDebugger;
        let debugger: Box<dyn Debugger<I>> = Box::new(TreeDebugger::new());
        Options {
            stacked_context: true,
            debugger: Some(debugger),
        }
    }

    #[cfg(not(debug_assertions))]
    fn default() -> Self {
        Options {
            stacked_context: false,
            debugger: None,
        }
    }
}

#[derive(Debug)]
pub struct Pear<I: Input> {
    pub input: I,
    #[doc(hidden)]
    pub emit_error: bool,
    #[doc(hidden)]
    pub options: Options<I>
}

impl<I: Input> Pear<I> {
    pub fn new<A>(input: A) -> Pear<I> where I: From<A> {
        Pear::from(I::from(input))
    }
}

impl<I: Input> From<I> for Pear<I> {
    fn from(input: I) -> Pear<I> {
        Pear { input, emit_error: true, options: Options::default() }
    }
}

impl<I: Input> std::ops::Deref for Pear<I> {
    type Target = I;
    fn deref(&self) -> &Self::Target {
        &self.input
    }
}

impl<I: Input> std::ops::DerefMut for Pear<I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.input
    }
}

impl<I: Input> Input for Pear<I> {
    type Token = I::Token;
    type Slice = I::Slice;
    type Many = I::Many;

    type Marker = I::Marker;
    type Context = I::Context;

    #[inline(always)]
    fn token(&mut self) -> Option<Self::Token> {
        self.input.token()
    }

    #[inline(always)]
    fn slice(&mut self, n: usize) -> Option<Self::Slice> {
        self.input.slice(n)
    }

    #[inline(always)]
    fn has(&mut self, n: usize) -> bool {
        self.input.has(n)
    }

    #[inline(always)]
    fn peek<F>(&mut self, cond: F) -> bool
        where F: FnMut(&Self::Token) -> bool
    {
        self.input.peek(cond)
    }

    #[inline(always)]
    fn peek_slice<F>(&mut self, n: usize, cond: F) -> bool
        where F: FnMut(&Self::Slice) -> bool
    {
        self.input.peek_slice(n, cond)
    }

    #[inline(always)]
    fn eat<F>(&mut self, cond: F) -> Option<Self::Token>
        where F: FnMut(&Self::Token) -> bool
    {
        self.input.eat(cond)
    }

    #[inline(always)]
    fn eat_slice<F>(&mut self, n: usize, cond: F) -> Option<Self::Slice>
        where F: FnMut(&Self::Slice) -> bool
    {
        self.input.eat_slice(n, cond)
    }

    #[inline(always)]
    fn take<F>(&mut self, cond: F) -> Self::Many
        where F: FnMut(&Self::Token) -> bool
    {
        self.input.take(cond)
    }

    #[inline(always)]
    fn skip<F>(&mut self, cond: F) -> usize
        where F: FnMut(&Self::Token) -> bool
    {
        self.input.skip(cond)
    }

    #[inline(always)]
    fn mark(&mut self, info: &ParserInfo) -> Self::Marker {
        self.input.mark(info)
    }

    #[inline(always)]
    fn context(&mut self, mark: Self::Marker) -> Self::Context {
        self.input.context(mark)
    }
}

impl<I: Input + Rewind> Rewind for Pear<I> {
    fn rewind_to(&mut self, marker: Self::Marker) {
        self.input.rewind_to(marker)
    }
}
