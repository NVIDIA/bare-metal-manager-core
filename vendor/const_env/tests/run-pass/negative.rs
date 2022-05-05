extern crate const_env;

use const_env::from_env;

#[from_env]
const NEGATIVE_I16: i16 = 0;

#[from_env]
const NEGATIVE_ISIZE: isize = -1;

#[from_env]
const NEGATIVE_F32: f32 = 0.0;

fn main() {
    assert_eq!(-123, NEGATIVE_I16);
    assert_eq!(-321, NEGATIVE_ISIZE);
    assert_eq!(-456.0, NEGATIVE_F32);
}