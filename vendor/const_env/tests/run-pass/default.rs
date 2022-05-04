extern crate const_env;

use const_env::from_env;

#[from_env]
const DEFAULT_CHAR: char = 'A';

#[from_env("DEFAULT_BYTE_STR")]
const DEFAULT_BYTE_STR: &'static [u8] = b"abcdefg";

fn main() {
    assert_eq!('A', DEFAULT_CHAR);
    assert_eq!(b"abcdefg", DEFAULT_BYTE_STR);
}