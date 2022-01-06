use pear::input::Span;
use pear::{macros::*, parsers::*};

type FourMarkers = (usize, usize, usize, usize);
type Input<'a> = pear::input::Pear<pear::input::Text<'a>>;
type Result<'a, T> = pear::input::Result<T, Input<'a>>;

#[parser]
fn simple<'a>(input: &mut Input<'a>) -> Result<'a, FourMarkers> {
    let first = parse_last_marker!();
    eat('.')?;
    let second = parse_last_marker!();
    eat_slice("..")?;
    let third = parse_last_marker!();
    eat_slice("..")?;
    let fourth = parse_last_marker!();
    (first, second, third, fourth)
}

#[parser]
fn simple_updating<'a>(input: &mut Input<'a>) -> Result<'a, FourMarkers> {
    let first = parse_current_marker!();
    eat('.')?;
    let second = parse_current_marker!();
    eat_slice("..")?;
    let third = parse_current_marker!();
    eat_slice("..")?;
    let fourth = parse_current_marker!();
    (first, second, third, fourth)
}

#[parser]
fn resetting<'a>(input: &mut Input<'a>) -> Result<'a, FourMarkers> {
    let first = parse_last_marker!();
    eat('.')?;
    parse_mark!();
    let second = parse_last_marker!();
    eat_slice("..")?;
    let third = parse_last_marker!();
    eat_slice("..")?;
    parse_mark!();
    let fourth = parse_last_marker!();
    (first, second, third, fourth)
}

#[test]
fn test_simple_marker() {
    let result = parse!(simple: Input::new(".....")).unwrap();
    assert_eq!(result, (0, 0, 0, 0));
}

#[test]
fn test_updating_marker() {
    let result = parse!(simple_updating: Input::new(".....")).unwrap();
    assert_eq!(result, (0, 1, 3, 5));
}

#[test]
fn test_resetting_marker() {
    let result = parse!(resetting: Input::new(".....")).unwrap();
    assert_eq!(result, (0, 1, 1, 5));
}

type TwoSpans<'a> = (Span<'a>, Span<'a>);

#[parser]
fn context<'a>(input: &mut Input<'a>) -> Result<'a, TwoSpans<'a>> {
    eat_slice("...")?;
    let first = parse_context!();
    eat('\n')?;
    eat_slice("..")?;
    let second = parse_context!();
    (first, second)
}

#[parser]
fn resetting_context<'a>(input: &mut Input<'a>) -> Result<'a, TwoSpans<'a>> {
    eat_slice("...")?;
    let first = parse_context!();
    eat('\n')?;
    parse_mark!();
    eat_slice("..")?;
    let second = parse_context!();
    (first, second)
}

#[test]
fn test_context() {
    let (first, second) = parse!(context: Input::new("...\n..")).unwrap();

    assert_eq!(first, Span {
        start: (1, 1, 0),
        end: (1, 4, 3),
        snippet: Some("..."),
        cursor: Some('\n'),
    });

    assert_eq!(second, Span {
        start: (1, 1, 0),
        end: (2, 3, 6),
        snippet: Some("...\n.."),
        cursor: None,
    });
}

#[test]
fn test_resetting_context() {
    let (first, second) = parse!(resetting_context: Input::new("...\n..")).unwrap();

    assert_eq!(first, Span {
        start: (1, 1, 0),
        end: (1, 4, 3),
        snippet: Some("..."),
        cursor: Some('\n'),
    });

    assert_eq!(second, Span {
        start: (2, 1, 4),
        end: (2, 3, 6),
        snippet: Some(".."),
        cursor: None,
    });
}
