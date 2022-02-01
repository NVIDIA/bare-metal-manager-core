# slug
A small library for generating [slugs][wikipedia] from unicode strings.

Documentation: https://docs.rs/slug

[wikipedia]: https://en.wikipedia.org/wiki/Semantic_URL#Slug

## Usage
```rust
extern crate slug;
use slug::slugify;

let slug = slugify("Hello world");
```
