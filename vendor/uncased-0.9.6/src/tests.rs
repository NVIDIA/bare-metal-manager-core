#![allow(deprecated)]

use crate::UncasedStr;

use core::hash::{Hash, Hasher, SipHasher};

fn hash<T: Hash>(t: &T) -> u64 {
    let mut s = SipHasher::new();
    t.hash(&mut s);
    s.finish()
}

macro_rules! assert_uncased_eq {
    ($($string:expr),+) => ({
        let strings = [$($string),+];

        for i in 0..strings.len() {
            for j in i..strings.len() {
                let (str_a, str_b) = (strings[i], strings[j]);
                let ascii_a = UncasedStr::new(str_a);
                let ascii_b = UncasedStr::new(str_b);
                assert_eq!(ascii_a, ascii_b);
                assert_eq!(hash(&ascii_a), hash(&ascii_b));
                assert_eq!(ascii_a, str_a);
                assert_eq!(ascii_b, str_b);
                assert_eq!(ascii_a, str_b);
                assert_eq!(ascii_b, str_a);
            }
        }
    })
}

#[test]
fn test_case_insensitive() {
    assert_uncased_eq!["a", "A"];
    assert_uncased_eq!["Aa", "aA", "AA", "aa"];
    assert_uncased_eq!["a a", "a A", "A A", "a a"];
    assert_uncased_eq!["foobar", "FOOBAR", "FooBar", "fOObAr", "fooBAR"];
    assert_uncased_eq!["", ""];
    assert_uncased_eq!["content-type", "Content-Type", "CONTENT-TYPE"];
}

#[test]
fn test_case_cmp() {
    assert!(UncasedStr::new("foobar") == UncasedStr::new("FOOBAR"));
    assert!(UncasedStr::new("a") == UncasedStr::new("A"));

    assert!(UncasedStr::new("a") < UncasedStr::new("B"));
    assert!(UncasedStr::new("A") < UncasedStr::new("B"));
    assert!(UncasedStr::new("A") < UncasedStr::new("b"));

    assert!(UncasedStr::new("aa") > UncasedStr::new("a"));
    assert!(UncasedStr::new("aa") > UncasedStr::new("A"));
    assert!(UncasedStr::new("AA") > UncasedStr::new("a"));
    assert!(UncasedStr::new("AA") > UncasedStr::new("a"));
    assert!(UncasedStr::new("Aa") > UncasedStr::new("a"));
    assert!(UncasedStr::new("Aa") > UncasedStr::new("A"));
    assert!(UncasedStr::new("aA") > UncasedStr::new("a"));
    assert!(UncasedStr::new("aA") > UncasedStr::new("A"));
}
