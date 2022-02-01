use serde::de::Deserialize;
use serde::ser::{self, Serialize};

use crate::UncasedStr;

impl<'a, 'de: 'a> Deserialize<'de> for &'a UncasedStr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: serde::Deserializer<'de>
    {
        Ok(<&str>::deserialize(deserializer)?.into())
    }
}

impl<'a> Serialize for &'a UncasedStr {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "with-serde-alloc")]
mod uncased_alloc {
    use super::*;
    use crate::Uncased;

    impl<'a, 'de> Deserialize<'de> for Uncased<'a> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: serde::Deserializer<'de>
        {
            Ok(alloc::string::String::deserialize(deserializer)?.into())
        }
    }

    impl<'a> Serialize for Uncased<'a> {
        fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(self.as_str())
        }
    }
}
