//! An optional implementation of serialization/deserialization.
use super::LinkedHashSet;
use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Formatter, Result as FmtResult};
use std::hash::{BuildHasher, Hash};
use std::marker::PhantomData;

impl<K, S> Serialize for LinkedHashSet<K, S>
where
    K: Serialize + Eq + Hash,
    S: BuildHasher,
{
    #[inline]
    fn serialize<T>(&self, serializer: T) -> Result<T::Ok, T::Error>
    where
        T: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for el in self {
            seq.serialize_element(el)?;
        }
        seq.end()
    }
}

#[derive(Debug)]
pub struct LinkedHashSetVisitor<K> {
    marker: PhantomData<fn() -> LinkedHashSet<K>>,
}

impl<K> Default for LinkedHashSetVisitor<K> {
    fn default() -> Self {
        LinkedHashSetVisitor {
            marker: PhantomData,
        }
    }
}

impl<'de, K> Visitor<'de> for LinkedHashSetVisitor<K>
where
    K: Deserialize<'de> + Eq + Hash,
{
    type Value = LinkedHashSet<K>;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "a set")
    }

    #[inline]
    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(LinkedHashSet::new())
    }

    #[inline]
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = LinkedHashSet::with_capacity(seq.size_hint().unwrap_or(0));

        while let Some(element) = seq.next_element()? {
            values.insert(element);
        }

        Ok(values)
    }
}

impl<'de, K> Deserialize<'de> for LinkedHashSet<K>
where
    K: Deserialize<'de> + Eq + Hash,
{
    fn deserialize<D>(deserializer: D) -> Result<LinkedHashSet<K>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(LinkedHashSetVisitor::default())
    }
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod test {
    extern crate serde_test;

    use self::serde_test::{assert_tokens, Token};
    use super::*;

    #[test]
    fn serde_empty() {
        let set = LinkedHashSet::<char>::new();

        assert_tokens(&set, &[Token::Seq { len: Some(0) }, Token::SeqEnd]);
    }

    #[test]
    fn serde_non_empty() {
        let mut set = LinkedHashSet::new();
        set.insert('b');
        set.insert('a');
        set.insert('c');

        assert_tokens(
            &set,
            &[
                Token::Seq { len: Some(3) },
                Token::Char('b'),
                Token::Char('a'),
                Token::Char('c'),
                Token::SeqEnd,
            ],
        );
    }
}
