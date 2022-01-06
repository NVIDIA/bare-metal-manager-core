use crate::input::{Show, ParserInfo};

pub use crate::expected::Expected;

#[derive(Debug, Clone)]
pub struct ParseError<C, E> {
    pub error: E,
    pub info: ErrorInfo<C>,
    pub stack: Vec<ErrorInfo<C>>,
}

#[derive(Debug, Clone)]
pub struct ErrorInfo<C> {
    pub parser: ParserInfo,
    pub context: C,
}

impl<C> ErrorInfo<C> {
    pub fn new(parser: ParserInfo, context: C) -> Self {
        Self { parser, context }
    }
}

impl<C, E> ParseError<C, E> {
    pub fn new(parser: ParserInfo, error: E, context: C) -> ParseError<C, E> {
        ParseError { error, info: ErrorInfo::new(parser, context), stack: vec![] }
    }

    pub fn push_info(&mut self, parser: ParserInfo, context: C) {
        self.stack.push(ErrorInfo::new(parser, context));
    }

    #[inline(always)]
    pub fn into<E2: From<E>>(self) -> ParseError<C, E2> {
        ParseError {
            error: self.error.into(),
            info: self.info,
            stack: self.stack,
        }
    }
}

impl<C: Show, E: std::fmt::Display> std::fmt::Display for ParseError<C, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(feature = "color")] yansi::Paint::disable();
        write!(f, "{} ({})", self.error, &self.info.context as &dyn Show)?;
        #[cfg(feature = "color")] yansi::Paint::enable();
        for info in &self.stack {
            write!(f, "\n + {}", info.parser.name)?;
            write!(f, " {}", &info.context as &dyn Show)?;
        }

        Ok(())
    }
}
