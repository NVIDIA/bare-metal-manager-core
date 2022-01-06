use pear::{macros::*, parsers::*};

type Input<'a> = pear::input::Pear<pear::input::Text<'a>>;
type Result<'a, T> = pear::input::Result<T, Input<'a>>;

#[parser(rewind, peek)]
fn ab<'a>(input: &mut Input<'a>) -> Result<'a, ()> {
    eat('a')?;
    eat('b')?;
    eof()?;
}

#[parser(rewind, peek)]
fn abc<'a>(input: &mut Input<'a>) -> Result<'a, ()> {
    eat('a')?;
    eat('b')?;
    eat('c')?;
    eof()?;
}

#[parser(rewind, peek)]
fn abcd<'a>(input: &mut Input<'a>) -> Result<'a, ()> {
    eat('a')?;
    eat('b')?;
    eat('c')?;
    eat('d')?;
    eof()?;
}

#[parser]
fn combo<'a>(input: &mut Input<'a>) -> Result<'a, &'a str> {
    switch! {
        ab() => eat_slice("ab")?,
        abc() => eat_slice("abc")?,
        abcd() => eat_slice("abcd")?,
        _ => parse_error!("not ab, abc, or abcd")?
    }
}

#[test]
fn test_peeking_ab() {
    let result = parse!(combo: Input::new("ab")).unwrap();
    assert_eq!(result, "ab")
}

#[test]
fn test_peeking_abc() {
    let result = parse!(combo: Input::new("abc")).unwrap();
    assert_eq!(result, "abc")
}

#[test]
fn test_peeking_abcd() {
    let result = parse!(combo: Input::new("abcd")).unwrap();
    assert_eq!(result, "abcd")
}

#[test]
fn test_peeking_fail() {
    let result = parse!(combo: Input::new("a"));
    assert!(result.is_err());

    let result = parse!(combo: Input::new("abcdef"));
    assert!(result.is_err());
}
