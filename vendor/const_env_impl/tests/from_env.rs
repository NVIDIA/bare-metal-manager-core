use const_env_impl::{from_env, TestEnv};

use proc_macro2::TokenStream;
use quote::quote;

#[test]
fn test_str() {
    let env = TestEnv::builder()
        .set("MYVAR", "world")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: &'static str = "Hello";
    };
    let expected: TokenStream = quote! {
        const MYVAR: &'static str = "world";
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_str_with_escapes() {
    let env = TestEnv::builder()
        .set("MYVAR", "world\\tfoo")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: &'static str = "Hello";
    };
    let expected: TokenStream = quote! {
        const MYVAR: &'static str = "world\tfoo";
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_byte_str() {
    let env = TestEnv::builder()
        .set("MYVAR", "world")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: &'static [u8] = b"Hello";
    };
    let expected: TokenStream = quote! {
        const MYVAR: &'static [u8] = b"world";
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_u32() {
    let env = TestEnv::builder()
        .set("MYVAR", "1")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: u32 = 0;
    };
    let expected: TokenStream = quote! {
        const MYVAR: u32 = 1;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_u32_with_suffix() {
    let env = TestEnv::builder()
        .set("MYVAR", "1u32")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: u32 = 0;
    };
    let expected: TokenStream = quote! {
        const MYVAR: u32 = 1u32;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_i64() {
    let env = TestEnv::builder()
        .set("MYVAR", "1")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: i64 = 0;
    };
    let expected: TokenStream = quote! {
        const MYVAR: i64 = 1;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_i64_with_suffix() {
    let env = TestEnv::builder()
        .set("MYVAR", "1i64")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: i64 = 0;
    };
    let expected: TokenStream = quote! {
        const MYVAR: i64 = 1i64;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_i64_with_negative() {
    let env = TestEnv::builder()
        .set("MYVAR", "-1")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: i64 = -0;
    };
    let expected: TokenStream = quote! {
        const MYVAR: i64 = -1;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_char() {
    let env = TestEnv::builder()
        .set("MYVAR", "b")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: char = 'a';
    };
    let expected: TokenStream = quote! {
        const MYVAR: char = 'b';
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_byte() {
    let env = TestEnv::builder()
        .set("MYVAR", "b")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: u8 = b'a';
    };
    let expected: TokenStream = quote! {
        const MYVAR: u8 = b'b';
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_byte_with_escape() {
    let env = TestEnv::builder()
        .set("MYVAR", "\\n")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: u8 = b'\t';
    };
    let expected: TokenStream = quote! {
        const MYVAR: u8 = b'\n';
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_f32() {
    let env = TestEnv::builder()
        .set("MYVAR", "1.0")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: f32 = 0.0;
    };
    let expected: TokenStream = quote! {
        const MYVAR: f32 = 1.0;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_f32_with_suffix() {
    let env = TestEnv::builder()
        .set("MYVAR", "1f32")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: f32 = 0.0;
    };
    let expected: TokenStream = quote! {
        const MYVAR: f32 = 1f32;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_f32_with_negative() {
    let env = TestEnv::builder()
        .set("MYVAR", "-1.0")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: f32 = -0.0;
    };
    let expected: TokenStream = quote! {
        const MYVAR: f32 = -1.0;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_bool() {
    let env = TestEnv::builder()
        .set("MYVAR", "true")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        const MYVAR: bool = false;
    };
    let expected: TokenStream = quote! {
        const MYVAR: bool = true;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_str_static() {
    let env = TestEnv::builder()
        .set("MYVAR", "world")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        static MYVAR: &'static str = "Hello";
    };
    let expected: TokenStream = quote! {
        static MYVAR: &'static str = "world";
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_i16_negative() {
    let env = TestEnv::builder()
        .set("MYVAR", "-123")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        static MYVAR: i16 = 0;
    };
    let expected: TokenStream = quote! {
        static MYVAR: i16 = -123;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_f32_negative() {
    let env = TestEnv::builder()
        .set("MYVAR", "-123.0")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        static MYVAR: f32 = 0.0;
    };
    let expected: TokenStream = quote! {
        static MYVAR: f32 = -123.0;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_default_name() {
    let env = TestEnv::builder()
        .set("MYVAR", "world")
        .build();
    let attr: TokenStream = TokenStream::new();
    let item: TokenStream = quote! {
        static MYVAR: &'static str = "Hello";
    };
    let expected: TokenStream = quote! {
        static MYVAR: &'static str = "world";
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}

#[test]
fn test_i32_negative_whitespace() {
    let env = TestEnv::builder()
        .set("MYVAR", " - 123 ")
        .build();
    let attr: TokenStream = quote! {
        ("MYVAR")
    };
    let item: TokenStream = quote! {
        static MYVAR: i32 = 0;
    };
    let expected: TokenStream = quote! {
        static MYVAR: i32 = -123;
    };
    let result = from_env(attr, item, env);
    assert_eq!(format!("{}", expected), format!("{}", result));
}