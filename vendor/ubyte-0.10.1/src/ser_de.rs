use serde::de::{self, Deserialize};
use serde::ser::{self, Serialize};

use crate::ByteUnit;

impl<'de> Deserialize<'de> for ByteUnit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: serde::Deserializer<'de>
    {
        deserializer.deserialize_u64(Visitor)
    }
}

macro_rules! visit_integer_fn {
    ($name:ident: $T:ty) => (
        fn $name<E: de::Error>(self, v: $T) -> Result<Self::Value, E> {
            Ok(v.into())
        }
    )
}

struct Visitor;

impl<'de> de::Visitor<'de> for Visitor {
    type Value = ByteUnit;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("a byte unit as an integer or string")
    }

    visit_integer_fn!(visit_i8: i8);
    visit_integer_fn!(visit_i16: i16);
    visit_integer_fn!(visit_i32: i32);
    visit_integer_fn!(visit_i64: i64);
    visit_integer_fn!(visit_i128: i128);

    visit_integer_fn!(visit_u8: u8);
    visit_integer_fn!(visit_u16: u16);
    visit_integer_fn!(visit_u32: u32);
    visit_integer_fn!(visit_u64: u64);
    visit_integer_fn!(visit_u128: u128);

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        v.parse().map_err(|_| E::invalid_value(de::Unexpected::Str(v), &"byte unit string"))
    }
}

impl Serialize for ByteUnit {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.as_u64())
    }
}

#[cfg(test)]
mod serde_tests {
    use serde_test::{assert_de_tokens, assert_ser_tokens, Token};
    use crate::ByteUnit;

    #[test]
    fn test_de() {
        let half_mib = ByteUnit::Kibibyte(512);
        assert_de_tokens(&half_mib, &[Token::Str("512 kib")]);
        assert_de_tokens(&half_mib, &[Token::Str("512 KiB")]);
        assert_de_tokens(&half_mib, &[Token::Str("512KiB")]);
        assert_de_tokens(&half_mib, &[Token::Str("524288")]);
        assert_de_tokens(&half_mib, &[Token::U32(524288)]);
        assert_de_tokens(&half_mib, &[Token::U64(524288)]);
        assert_de_tokens(&half_mib, &[Token::I32(524288)]);
        assert_de_tokens(&half_mib, &[Token::I64(524288)]);

        let one_mib = ByteUnit::Mebibyte(1);
        assert_de_tokens(&one_mib, &[Token::Str("1 mib")]);
        assert_de_tokens(&one_mib, &[Token::Str("1 MiB")]);
        assert_de_tokens(&one_mib, &[Token::Str("1mib")]);

        let zero = ByteUnit::Byte(0);
        assert_de_tokens(&zero, &[Token::Str("0")]);
        assert_de_tokens(&zero, &[Token::Str("0 B")]);
        assert_de_tokens(&zero, &[Token::U32(0)]);
        assert_de_tokens(&zero, &[Token::U64(0)]);
        assert_de_tokens(&zero, &[Token::I32(-34)]);
        assert_de_tokens(&zero, &[Token::I64(-2483)]);
    }

    #[test]
    fn test_ser() {
        let half_mib = ByteUnit::Kibibyte(512);
        assert_ser_tokens(&half_mib, &[Token::U64(512 << 10)]);

        let ten_bytes = ByteUnit::Byte(10);
        assert_ser_tokens(&ten_bytes, &[Token::U64(10)]);

        let zero = ByteUnit::Byte(0);
        assert_de_tokens(&zero, &[Token::U64(0)]);
    }
}
