patricia_tree
=============

[![patricia_tree](https://img.shields.io/crates/v/patricia_tree.svg)](https://crates.io/crates/patricia_tree)
[![Documentation](https://docs.rs/patricia_tree/badge.svg)](https://docs.rs/patricia_tree)
[![Actions Status](https://github.com/sile/patricia_tree/workflows/CI/badge.svg)](https://github.com/sile/patricia_tree/actions)
[![Coverage Status](https://coveralls.io/repos/github/sile/patricia_tree/badge.svg?branch=master)](https://coveralls.io/github/sile/patricia_tree?branch=master)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Memory-efficient data structures based on patricia tree (a.k.a, radix tree).

[Documentation](https://docs.rs/patricia_tree)

A common prefixes of the keys in a patricia tree are represented by a shared path.
So if the prefixes of the key set is highly redundant,
the memory usage of the resulting patricia tree will be drastically less than
more generic data structures (e.g., `BTreeMap`).

See [Radix tree](https://en.wikipedia.org/wiki/Radix_tree) for more details.

Examples
---------

```rust
use patricia_tree::PatriciaMap;

let mut map = PatriciaMap::new();
map.insert("foo", 1);
map.insert("bar", 2);
map.insert("baz", 3);
assert_eq!(map.len(), 3);

assert_eq!(map.get("foo"), Some(&1));
assert_eq!(map.get("bar"), Some(&2));
assert_eq!(map.get("baz"), Some(&3));
```

Benchmarks
-----------

```console
$ cargo run --example insert_lines --release -- --version 2> /dev/null
insert_lines 0.1.0

///
/// INPUT: Wikipedia
///
$ curl -s https://dumps.wikimedia.org/enwiki/latest/enwiki-latest-all-titles-in-ns0.gz | gzip -d > enwiki-latest-all-titles-in-ns0
$ du -hs enwiki-latest-all-titles-in-ns0
271M    enwiki-latest-all-titles-in-ns0

// HashSet
$ /usr/bin/time -f "# ELAPSED: %E\n# MEMORY: %M" cargo run --example insert_lines --release -- --kind hash < enwiki-latest-all-titles-in-ns0
# LINES: 13450823
# ELAPSED: 0:10.23
# MEMORY: 1001548  // 978 MB

// BTreeSet
$ /usr/bin/time -f "# ELAPSED: %E\n# MEMORY: %M" cargo run --example insert_lines --release -- --kind btree < enwiki-latest-all-titles-in-ns0
# LINES: 13450823
# ELAPSED: 0:10.90
# MEMORY: 1112068  // 1,086 MB

// PatriciaSet
$ /usr/bin/time -f "# ELAPSED: %E\n# MEMORY: %M" cargo run --example insert_lines --release -- --kind patricia < enwiki-latest-all-titles-in-ns0
# LINES: 13450823
# ELAPSED: 1:12.55
# MEMORY: 434340   // 424 MB

///
/// INPUT: Google 5-gram
///
$ curl -s http://storage.googleapis.com/books/ngrams/books/googlebooks-eng-all-5gram-20120701-0.gz | gzip -d > googlebooks-eng-all-5gram-20120701-0
$ du -hs googlebooks-eng-all-5gram-20120701-0
331M    googlebooks-eng-all-5gram-20120701-0

// HashSet
$ /usr/bin/time -f "# ELAPSED: %E\n# MEMORY: %M" cargo run --example insert_lines --release -- --kind hash < googlebooks-eng-all-5gram-20120701-0
# LINES: 9814743
# ELAPSED: 0:08.36
# MEMORY: 1115544  // 1,089 MB

// BTreeSet
$ /usr/bin/time -f "# ELAPSED: %E\n# MEMORY: %M" cargo run --example insert_lines --release -- --kind btree < googlebooks-eng-all-5gram-20120701-0
# LINES: 9814743
# ELAPSED: 0:06.85
# MEMORY: 942236   // 920 MB

// PatriciaSet
$ /usr/bin/time -f "# ELAPSED: %E\n# MEMORY: %M" cargo run --example insert_lines --release -- --kind patricia < googlebooks-eng-all-5gram-20120701-0
# LINES: 9814743
# ELAPSED: 0:25.62
# MEMORY: 223616   // 218 MB
```
