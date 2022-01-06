extern crate serde;

use self::serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use core::fmt;

use timezones::Tz;

impl Serialize for Tz {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.name())
    }
}

impl<'de> Deserialize<'de> for Tz {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Tz;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "an IANA timezone string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Tz, E> {
                value.parse::<Tz>().map_err(|e| E::custom(e))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(test)]
mod tests {
    extern crate serde_test;

    use self::serde_test::{assert_de_tokens_error, assert_tokens, Token};
    use timezones::Tz::{self, Etc__UTC, Europe__London, UTC};

    #[test]
    fn serde_ok_both_ways() {
        assert_tokens(&Europe__London, &[Token::String("Europe/London")]);
        assert_tokens(&Etc__UTC, &[Token::String("Etc/UTC")]);
        assert_tokens(&UTC, &[Token::String("UTC")]);
    }

    #[test]
    fn serde_de_error() {
        assert_de_tokens_error::<Tz>(
            &[Token::Str("Europe/L")],
            "'Europe/L' is not a valid timezone",
        );
        assert_de_tokens_error::<Tz>(&[Token::Str("")], "'' is not a valid timezone");
    }
}
