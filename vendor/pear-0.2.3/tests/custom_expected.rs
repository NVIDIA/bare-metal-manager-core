use std::borrow::Cow;

use pear::input::{Text, Pear, Span, Expected};
use pear::{macros::*, parsers::*};

type Result<'a, T> = pear::result::Result<T, Span<'a>, Error<'a>>;

#[derive(Debug)]
enum Error<'a> {
    Expected(Expected<Text<'a>>),
    Other {
        message: Cow<'static, str>,
        second: Option<Cow<'static, str>>
    }
}

impl<'a> From<String> for Error<'a> {
    fn from(message: String) -> Error<'a> {
        Error::Other { message: message.into(), second: None }
    }
}

impl<'a> From<&'static str> for Error<'a> {
    fn from(message: &'static str) -> Error<'a> {
        Error::Other { message: message.into(), second: None }
    }
}

impl<'a> From<Expected<Text<'a>>> for Error<'a> {
    fn from(other: Expected<Text<'a>>) -> Error<'a> {
        Error::Expected(other)
    }
}

impl_show_with!(Debug, Error<'_>);

#[parser]
fn combo<'a>(input: &mut Pear<Text<'a>>) -> Result<'a, ()> {
    let start = switch! {
        peek('a') => eat_slice("abc")?,
        peek('b') => eat_slice("bat")?,
        _ => parse_error!("either bat or abc, please")?
    };

    match start {
        "abc" => {
            eat_slice("def").or_else(|e| parse_error!(Error::Other {
                message: "def needs to follow abc".into(),
                second: Some(e.to_string().into())
            }))?;
        },
        "bat" => {
            eof().or_else(|_| parse_error!(Error::Other {
                message: "whoah whoah, bat must be at end".into(),
                second: None
            }))?;
        },
        _ => unreachable!("only two options")
    }
}

impl<'a> Error<'a> {
    fn assert_expected(self) {
        if let Error::Other { .. } = self {
            panic!("expected 'Expected', was 'Other'")
        }
    }

    fn assert_other(self) {
        if let Error::Expected(..) = self {
            panic!("expected 'Other', was 'Expected'")
        }
    }
}

#[test]
fn test_custom_expect_ok() {
    let result = parse!(combo: Text::from("bat"));
    assert!(result.is_ok());

    let result = parse!(combo: Text::from("abcdef"));
    assert!(result.is_ok());
}

#[test]
fn test_custom_expect_expected() {
    let result = parse!(combo: Text::from("ab"));
    result.unwrap_err().error.assert_expected();

    let result = parse!(combo: Text::from("ba"));
    result.unwrap_err().error.assert_expected();
}

#[test]
fn test_custom_expect_other() {
    let result = parse!(combo: Text::from("abc"));
    result.unwrap_err().error.assert_other();

    let result = parse!(combo: Text::from("abcd"));
    result.unwrap_err().error.assert_other();

    let result = parse!(combo: Text::from("batfoo"));
    result.unwrap_err().error.assert_other();
}
