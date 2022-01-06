use crate::error::Expected;
use crate::input::{Input, Pear, Length, Token, Slice, Result, Rewind};
use crate::combinators::succeeds;
use crate::macros::parser;

// TODO: provide more basic parsers in pear
//   - [f32, f64, i8, i32, ..., bool, etc.]: one for all reasonable built-ins
//   - quoted_string(allowed): '"' allowed* '"'
//   - escaped string, with some way to configure escapes

#[inline]
fn expected_token<T, I>(
    input: &mut Pear<I>,
    token: Option<T>
) -> Expected<I::Token, I::Slice>
    where T: Token<I>, I: Input
{
    // TODO: Have some way to test this is being called minimally.
    if input.emit_error {
        Expected::token(token.as_ref(), input.token())
    } else {
        Expected::Elided
    }
}

#[inline]
fn expected_slice<S, I>(
    input: &mut Pear<I>,
    slice: S
) -> Expected<I::Token, I::Slice>
    where S: Slice<I>, I: Input
{
    // TODO: Have some way to test this is being called minimally.
    if input.emit_error {
        Expected::slice(Some(&slice), input.slice(slice.len()))
    } else {
        Expected::Elided
    }
}

/// Eats the current token if it is `token`.
#[parser(raw)]
pub fn eat<I, T>(input: &mut Pear<I>, token: T) -> Result<I::Token, I>
    where I: Input, T: Token<I>
{
    match input.eat(|t| &token == t) {
        Some(token) => Ok(token),
        None => return parse_error!(expected_token(input, Some(token)))
    }
}

/// Eats the token `token` if `cond` holds on the current token.
#[parser(raw)]
pub fn eat_if<I, F>(input: &mut Pear<I>, cond: F) -> Result<I::Token, I>
    where I: Input, F: FnMut(&I::Token) -> bool
{
    match input.eat(cond) {
        Some(token) => Ok(token),
        None => parse_error!(expected_token::<I::Token, _>(input, None))
    }
}

/// Eats the current token unconditionally. Fails if there are no tokens.
#[parser(raw)]
pub fn eat_any<I: Input>(input: &mut Pear<I>) -> Result<I::Token, I> {
    match input.eat(|_| true) {
        Some(token) => Ok(token),
        None => return parse_error!(Expected::Token(None, None))
    }
}

/// Skips the current token unconditionally. Fails if there are no tokens.
#[parser(raw)]
pub fn skip_any<I: Input>(input: &mut Pear<I>) -> Result<(), I> {
    let mut skipped = false;
    input.skip(|_| {
        if !skipped {
            skipped = true;
            true
        } else {
            false
        }
    });

    match skipped {
        true => Ok(()),
        false => return parse_error!(Expected::Token(None, None)),
    }
}

/// Eats the current slice if it is `slice`.
#[parser(raw)]
pub fn eat_slice<I, S>(input: &mut Pear<I>, slice: S) -> Result<I::Slice, I>
    where I: Input, S: Slice<I>
{
    match input.eat_slice(slice.len(), |s| &slice == s) {
        Some(slice) => Ok(slice),
        None => return parse_error!(expected_slice(input, slice))
    }
}

/// Succeeds if the current token is `token`.
#[parser(raw)]
pub fn peek<I, T>(input: &mut Pear<I>, token: T) -> Result<(), I>
    where I: Input, T: Token<I>
{
    match input.peek(|t| &token == t) {
        true => Ok(()),
        false => return parse_error!(expected_token(input, Some(token)))
    }
}

/// Succeeds if `cond` holds for the current token.
#[parser(raw)]
pub fn peek_if_copy<I, F>(input: &mut Pear<I>, cond: F) -> Result<I::Token, I>
    where I: Input, F: FnMut(&I::Token) -> bool
{
    match input.peek(cond) {
        true => Ok(input.token().unwrap()),
        false => parse_error!(expected_token::<I::Token, _>(input, None))
    }
}

/// Succeeds if `cond` holds for the current token.
#[parser(raw)]
pub fn peek_if<I, F>(input: &mut Pear<I>, cond: F) -> Result<(), I>
    where I: Input, F: FnMut(&I::Token) -> bool
{
    match input.peek(cond) {
        true => Ok(()),
        false => parse_error!(expected_token::<I::Token, _>(input, None))
    }
}

/// Succeeds if the current slice is `slice`.
#[parser(raw)]
pub fn peek_slice<I, S>(input: &mut Pear<I>, slice: S) -> Result<(), I>
    where I: Input, S: Slice<I>
{
    match input.peek_slice(slice.len(), |s| &slice == s) {
        true => Ok(()),
        false => return parse_error!(expected_slice(input, slice)),
    }
}

/// Succeeds if the current slice is `slice`.
#[parser(raw)]
pub fn peek_slice_if<I, F>(input: &mut Pear<I>, len: usize, cond: F) -> Result<(), I>
    where I: Input, F: FnMut(&I::Slice) -> bool
{
    match input.peek_slice(len, cond) {
        true => Ok(()),
        false => return parse_error!(Expected::Slice(None, None)),
    }
}

/// Returns the current token.
#[parser(raw)]
pub fn peek_any<I: Input>(input: &mut Pear<I>) -> Result<I::Token, I> {
    match input.token() {
        Some(peeked) => Ok(peeked),
        None => return parse_error!(Expected::Token(None, None)),
    }
}

/// Skips tokens while `cond` matches.
#[parser(raw)]
pub fn skip_while<I, F>(input: &mut Pear<I>, cond: F) -> Result<usize, I>
    where I: Input, F: FnMut(&I::Token) -> bool
{
    Ok(input.skip(cond))
}

/// Consumes tokens while `cond` matches and returns them. Succeeds even if no
/// tokens match.
#[parser(raw)]
pub fn take_while<I, F>(input: &mut Pear<I>, cond: F) -> Result<I::Many, I>
    where I: Input, F: FnMut(&I::Token) -> bool
{
    Ok(input.take(cond))
}

/// Consumes no tokens. Always succeeds. Equivalent to `take_while(|_| false)`.
#[parser(raw)]
pub fn none<I: Input>(input: &mut Pear<I>) -> Result<I::Many, I> {
    take_while(input, |_| false)
}

/// Consumes tokens while `cond` matches on a continously growing slice
/// beginning at a length of `0` and ending when `cond` fails. Returns the slice
/// between `0` and `cond` failing. Errors if no such slice exists.
#[parser(raw)]
pub fn take_while_slice<I, F>(input: &mut Pear<I>, mut f: F) -> Result<I::Slice, I>
    where I: Input, F: FnMut(&I::Slice) -> bool
{
    let mut len = 0;
    let mut last_good = None;
    loop {
        match input.slice(len) {
            // There's a slice and it matches the condition, keep going!
            Some(ref slice) if f(slice) => {
                last_good = Some(len);
                len += 1;
            }
            // There's no slice of length `n`, but there _might_ be a slice of
            // length `n + 1`, so we  need to keep trying.
            None if input.has(len + 1) => len += 1,
            // There are no more slices or the match failed. We're done.
            _ => break,
        }
    }

    match last_good {
        Some(len) => Ok(input.eat_slice(len, |_| true).expect("slice exists")),
        None => return parse_error!(Expected::Slice(None, None)),
    }
}

/// Consumes tokens while `cond` matches on a window of tokens of size `n` and
/// returns all of the tokens prior to the first failure to match. For example,
/// given a string of "aaab" and a size 2 window predicate of `window == "aa"`,
/// the return value is `"aa"` as the first failure to match is at `"ab"`.
///
/// Always succeeds. If no tokens match, the result will be empty. If there are
/// fewer than `n` tokens, takes all tokens and returns them.
#[parser(raw)]
pub fn take_while_window<I, F>(input: &mut Pear<I>, n: usize, mut f: F) -> Result<I::Many, I>
    where I: Input + Rewind, F: FnMut(&I::Slice) -> bool
{
    if !input.has(n) {
        return Ok(input.take(|_| true));
    }

    let start = parse_current_marker!();
    let mut tokens = 0;
    loop {
        // See `take_while_slice` for  an explanation of these arms.
        match input.slice(n) {
            Some(ref slice) if f(slice) => {
                if !succeeds(input, skip_any) { break; }
                tokens += 1;
            }
            None if input.has(n + 1) => {
                if !succeeds(input, skip_any) { break; }
                tokens += 1;
            }
            _ => break,
        }
    }

    input.rewind_to(start);
    Ok(input.take(|_| match tokens > 0 {
        true => { tokens -= 1; true },
        false => false
    }))
}

/// Consumes tokens while `cond` matches on a window of tokens of size `n` and
/// returns them. Fails if there no tokens match, otherwise returns all of the
/// tokens before the first failure.
#[parser(raw)]
pub fn take_some_while_window<I, F>(input: &mut Pear<I>, n: usize, f: F) -> Result<I::Many, I>
    where I: Input + Rewind, F: FnMut(&I::Slice) -> bool
{
    let result = take_while_window(n, f)?;
    if result.is_empty() {
        return parse_error!(Expected::Slice(None, None));
    }

    Ok(result)
}

/// Consumes tokens while `cond` matches on a window of tokens of size `n` and
/// returns them. Fails if there aren't at least `n` tokens, otherwise always
/// otherwise always succeeds. If no tokens match, the result will be empty.
#[parser(raw)]
pub fn take_while_some_window<I, F>(input: &mut Pear<I>, n: usize, f: F) -> Result<I::Many, I>
    where I: Input + Rewind, F: FnMut(&I::Slice) -> bool
{
    if !input.has(n) {
        return parse_error!(Expected::Slice(None, None));
    }

    take_while_window(input, n, f)
}

/// Consumes tokens while `cond` matches on a window of tokens of size `n` and
/// returns them. Fails if there aren't at least `n` tokens or if no tokens
/// match, otherwise returns all of the tokens before the first failure.
#[parser(raw)]
pub fn take_some_while_some_window<I, F>(input: &mut Pear<I>, n: usize, f: F) -> Result<I::Many, I>
    where I: Input + Rewind, F: FnMut(&I::Slice) -> bool
{
    if !input.has(n) {
        return parse_error!(Expected::Slice(None, None));
    }

    take_some_while_window(input, n, f)
}

/// Consumes tokens while `cond` matches on a window of tokens of size `n` and
/// returns them. Succeeds even if no tokens match.
#[parser(raw)]
pub fn take_until_slice<I, S>(input: &mut Pear<I>, slice: S) -> Result<I::Many, I>
    where I: Input + Rewind, S: Slice<I>
{
    take_while_window(input, slice.len(), |s| &slice != s)
}

/// Consumes tokens while `cond` matches and returns them. Succeeds only if at
/// least one token matched `cond`.
#[parser(raw)]
pub fn take_some_while<I, F>(input: &mut Pear<I>, cond: F) -> Result<I::Many, I>
    where I: Input, F: FnMut(&I::Token) -> bool
{
    let value = input.take(cond);
    if value.len() == 0 {
        return parse_error!(Expected::Token(None, None));
    }

    Ok(value)
}

/// Consumes tokens while `cond` matches and the token is not `until`. Succeeds
/// even if no tokens match.
#[parser(raw)]
pub fn take_while_until<I, T, F>(
    input: &mut Pear<I>,
    mut cond: F,
    until: T,
) -> Result<I::Many, I>
    where I: Input,
          T: Token<I>,
          F: FnMut(&I::Token) -> bool
{
    take_while(input, |t| cond(t) && (&until != t))
}

/// Consumes tokens while `cond` matches and the token is not `until`. Succeeds
/// only if at least one token matched `cond`.
#[parser(raw)]
pub fn take_some_while_until<I, T, F>(
    input: &mut Pear<I>,
    mut cond: F,
    until: T,
) -> Result<I::Many, I>
    where I: Input,
          T: Token<I>,
          F: FnMut(&I::Token) -> bool
{
    take_some_while(input, |t| cond(t) && (&until != t))
}

/// Takes at most `n` tokens.
#[parser(raw)]
pub fn take_n<I: Input>(input: &mut Pear<I>, n: usize) -> Result<I::Many, I> {
    let mut i = 0;
    Ok(input.take(|_| { let c = i < n; i += 1; c }))
}

/// Takes at most `n` tokens as long as `cond` holds.
#[parser(raw)]
pub fn take_n_while<I, F>(input: &mut Pear<I>, n: usize, mut cond: F) -> Result<I::Many, I>
    where I: Input, F: FnMut(&I::Token) -> bool
{
    let mut i = 0;
    Ok(input.take(|c| { cond(c) && { let ok = i < n; i += 1; ok } }))
}

/// Take exactly `n` tokens, ensuring `cond` holds on all `n`.
#[parser(raw)]
pub fn take_n_if<I, F>(input: &mut Pear<I>, n: usize, mut cond: F) -> Result<I::Many, I>
    where I: Input, F: FnMut(&I::Token) -> bool
{
    let mut i = 0;
    let v = input.take(|c| { cond(c) && { let ok = i < n; i += 1; ok } });
    if v.len() != n {
        return parse_error!(Expected::Token(None, None));
    }

    Ok(v)
}

/// Parse a token stream that starts with `start` and ends with `end`, returning
/// all of the tokens in between. The tokens in between must match `cond`.
/// Succeeds even if there are no tokens between `start` and `end`.
#[parser(raw)]
pub fn delimited<I, T, F>(
    input: &mut Pear<I>,
    start: T,
    mut cond: F,
    end: T,
) -> Result<I::Many, I>
    where I: Input,
          T: Token<I>,
          F: FnMut(&I::Token) -> bool
{
    eat(start)?;
    let output = input.take(|t| cond(t) && (&end != t));
    eat(end)?;
    Ok(output)
}

/// Parse a token stream that starts with `start` and ends with `end`, returning
/// all of the tokens in between. The tokens in between must match `cond`. There
/// must be at least one token between `start` and `end`.
#[parser(raw)]
pub fn delimited_some<I, T, F>(
    input: &mut Pear<I>,
    start: T,
    mut cond: F,
    end: T,
) -> Result<I::Many, I>
    where I: Input,
          T: Token<I>,
          F: FnMut(&I::Token) -> bool
{
    eat(start)?;
    let output = take_some_while(|t| cond(t) && (&end != t))?;
    eat(end)?;
    Ok(output)
}

/// Succeeds only if the input has reached EOF.
#[parser(raw)]
pub fn eof<I: Input>(input: &mut Pear<I>) -> Result<(), I> {
    Ok(if input.has(1) {
        let next = input.token();
        parse_error!(Expected::Eof(next))?
    })
}

/// Like `delimited` but keeps the `start` and `end`.
#[parser(raw)]
pub fn enclosed<I, T, F>(
    input: &mut Pear<I>,
    start: T,
    mut cond: F,
    end: T,
) -> Result<I::Many, I>
    where I: Input,
          T: Token<I>,
          F: FnMut(&I::Token) -> bool
{
    enum State {
        Start,
        Inner,
        End
    }

    let mut state = State::Start;
    let value = input.take(|t| {
        match state {
            State::Start if &start == t => { state = State::Inner; true },
            State::Start => false,
            State::Inner if cond(t) => true,
            State::Inner if &end == t => { state = State::End; true },
            State::Inner => false,
            State::End => false,
        }
    });

    match state {
        State::Start => parse_error!(expected_token(input, Some(start))),
        State::Inner => parse_error!(expected_token(input, Some(end))),
        State::End => Ok(value)
    }
}
