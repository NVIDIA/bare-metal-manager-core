extern crate const_env;

use const_env::from_env;

#[from_env("SMOKE_STR")]
const SMOKE_STR: &'static str = "foo";

#[from_env("SMOKE_U32")]
const SMOKE_U32: u32 = 123;

fn main() {
    assert_eq!("bar", SMOKE_STR);
    assert_eq!(321, SMOKE_U32);
}