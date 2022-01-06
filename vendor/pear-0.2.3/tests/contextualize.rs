use pear::input::{Pear, Text};
use pear::{macros::*, parsers::*};

type Result<'a, T> = pear::input::Result<T, Text<'a>>;

macro_rules! parse_me {
    ([$n:expr; $i:expr; $m:expr; $T:ty] $e:expr) => {
        (eat_slice($i, "a")?, $e, eat_slice($i, "c")?).1
    }
}

#[parser]
fn combo<'a>(input: &mut Pear<Text<'a>>) -> Result<'a, &'a str> {
    parse_me!(eat_slice("b")?)
}

#[test]
fn text_contextualize() {
    let result = parse!(combo: Text::from("abc"));
    assert_eq!(result.unwrap(), "b");
}
