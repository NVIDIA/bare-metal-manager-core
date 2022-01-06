pub use crate::input::{Input, Rewind, Token, Slice, Show, ParserInfo};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Span<'a> {
    /// Start line/column/offset.
    pub start: (usize, usize, usize),
    /// End line/column/offset.
    pub end: (usize, usize, usize),
    /// Where the parser was pointing.
    pub cursor: Option<char>,
    /// Snippet between start and end.
    pub snippet: Option<&'a str>,
}

const SNIPPET_LEN: usize = 30;

impl<'a> Show for Span<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (a, b, _) = self.start;
        let (c, d, _) = self.end;

        if self.start == self.end {
            write!(f, "{}:{}", a, b)?;
        } else {
            write!(f, "{}:{} to {}:{}", a, b, c, d)?;
        }

        let write_snippet = |f: &mut std::fmt::Formatter<'_>, snippet: &str| {
            for c in snippet.escape_debug() { write!(f, "{}", c)?; }
            Ok(())
        };

        if let Some(snippet) = self.snippet {
            write!(f, " \"")?;
            if snippet.len() > SNIPPET_LEN + 6 {
                write_snippet(f, &snippet[..SNIPPET_LEN / 2])?;

                #[cfg(feature = "color")]
                write!(f, " {} ", yansi::Paint::blue("..."))?;

                #[cfg(not(feature = "color"))]
                write!(f, " ... ")?;

                let end_start = snippet.len() - SNIPPET_LEN / 2;
                write_snippet(f, &snippet[end_start..])?;
            } else {
                write_snippet(f, snippet)?;
            }

            if let Some(cursor) = self.cursor {
                #[cfg(feature = "color")]
                write!(f, "{}", yansi::Paint::blue(cursor.escape_debug()))?;

                #[cfg(not(feature = "color"))]
                write!(f, "{}", cursor.escape_debug())?;
            }
            write!(f, "\"")?;
        } else {
            #[cfg(feature = "color")]
            write!(f, " {}", yansi::Paint::blue("[EOF]"))?;

            #[cfg(not(feature = "color"))]
            write!(f, " [EOF]");
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Text<'a> {
    current: &'a str,
    start: &'a str,
}

impl<'a> From<&'a str> for Text<'a> {
    fn from(start: &'a str) -> Text<'a> {
        Text { start, current: start }
    }
}

impl Rewind for Text<'_> {
    fn rewind_to(&mut self, marker: Self::Marker) {
        self.current = &self.start[marker..];
    }
}

impl<'a> Input for Text<'a> {
    type Token = char;
    type Slice = &'a str;
    type Many = Self::Slice;

    type Marker = usize;
    type Context = Span<'a>;

    /// Returns a copy of the current token, if there is one.
    fn token(&mut self) -> Option<Self::Token> {
        self.current.token()
    }

    /// Returns a copy of the current slice of size `n`, if there is one.
    fn slice(&mut self, n: usize) -> Option<Self::Slice> {
        self.current.slice(n)
    }

    /// Checks if the current token fulfills `cond`.
    fn peek<F>(&mut self, cond: F) -> bool
        where F: FnMut(&Self::Token) -> bool
    {
        self.current.peek(cond)
    }

    /// Checks if the current slice of size `n` (if any) fulfills `cond`.
    fn peek_slice<F>(&mut self, n: usize, cond: F) -> bool
        where F: FnMut(&Self::Slice) -> bool
    {
        self.current.peek_slice(n, cond)
    }

    /// Checks if the current token fulfills `cond`. If so, the token is
    /// consumed and returned. Otherwise, returns `None`.
    fn eat<F>(&mut self, cond: F) -> Option<Self::Token>
        where F: FnMut(&Self::Token) -> bool
    {
        self.current.eat(cond)
    }

    /// Checks if the current slice of size `n` (if any) fulfills `cond`. If so,
    /// the slice is consumed and returned. Otherwise, returns `None`.
    fn eat_slice<F>(&mut self, n: usize, cond: F) -> Option<Self::Slice>
        where F: FnMut(&Self::Slice) -> bool
    {
        self.current.eat_slice(n, cond)
    }

    /// Takes tokens while `cond` returns true, collecting them into a
    /// `Self::Many` and returning it.
    fn take<F>(&mut self, cond: F) -> Self::Many
        where F: FnMut(&Self::Token) -> bool
    {
        self.current.take(cond)
    }

    /// Skips tokens while `cond` returns true. Returns the number of skipped
    /// tokens.
    fn skip<F>(&mut self, cond: F) -> usize
        where F: FnMut(&Self::Token) -> bool
    {
        self.current.skip(cond)
    }

    /// Returns `true` if there are at least `n` tokens remaining.
    fn has(&mut self, n: usize) -> bool {
        self.current.has(n)
    }

    #[inline(always)]
    fn mark(&mut self, _: &ParserInfo) -> Self::Marker {
        self.start.len() - self.current.len()
    }

    fn context(&mut self, mark: Self::Marker) -> Self::Context {
        let cursor = self.token();
        let bytes_read = self.start.len() - self.current.len();
        let pos = if bytes_read == 0 {
            Span { start: (1, 1, 0), end: (1, 1, 0), snippet: None, cursor }
        } else {
            let start_offset = mark;
            let end_offset = bytes_read;

            let to_start_str = &self.start[..start_offset];
            let (start_line, start_col) = line_col(to_start_str);
            let start = (start_line, start_col, start_offset);

            let to_current_str = &self.start[..bytes_read];
            let (end_line, end_col) = line_col(to_current_str);
            let end = (end_line, end_col, bytes_read);

            let snippet = if end_offset <= self.start.len() {
                Some(&self.start[start_offset..end_offset])
            } else {
                None
            };

            Span { start, end, cursor, snippet }
        };

        pos
    }
}

fn line_col(string: &str) -> (usize, usize) {
    if string.is_empty() {
        return (1, 1);
    }

    let (line_count, last_line) = string.lines().enumerate().last().unwrap();
    if string.ends_with('\n') {
        (line_count + 2, 1)
    } else {
        (line_count + 1, last_line.len() + 1)
    }
}
