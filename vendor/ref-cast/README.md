RefCast
=======

[<img alt="github" src="https://img.shields.io/badge/github-dtolnay/ref--cast-8da0cb?style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/dtolnay/ref-cast)
[<img alt="crates.io" src="https://img.shields.io/crates/v/ref-cast.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/ref-cast)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-ref--cast-66c2a5?style=for-the-badge&labelColor=555555&logoColor=white&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">](https://docs.rs/ref-cast)
[<img alt="build status" src="https://img.shields.io/github/workflow/status/dtolnay/ref-cast/CI/master?style=for-the-badge" height="20">](https://github.com/dtolnay/ref-cast/actions?query=branch%3Amaster)

Safely cast `&T` to `&U` where the struct `U` contains a single field of
type `T`.

```toml
[dependencies]
ref-cast = "1.0"
```

## Basic example

```rust
use ref_cast::RefCast;

#[derive(RefCast)]
#[repr(transparent)]
struct U(String);

fn main() {
    let s = String::new();

    // Safely cast from `&String` to `&U`.
    let u = U::ref_cast(&s);
}
```

Note that either of `#[repr(C)]` or `#[repr(transparent)]` is required in order
for the conversion to be sound. The derive macro will refuse to compile if
neither is present.

## Realistic example

Suppose we have a multidimensional array represented in a flat buffer in
row-major order for performance reasons, but we want to expose an indexing
operation that works in column-major order because it is more intuitive in
the context of our application.

```rust
const MAP_WIDTH: usize = 4;

struct Tile(u8);

struct TileMap {
    storage: Vec<Tile>,
}

// `tilemap[x][y]` should give us `tilemap.storage[y * MAP_WIDTH + x]`.
```

The signature of the [`Index`] trait in Rust is such that the output is
forced to be borrowed from the type being indexed. So something like the
following is not going to work.

[`Index`]: https://doc.rust-lang.org/std/ops/trait.Index.html

```rust
struct Column<'a> {
    tilemap: &'a TileMap,
    x: usize,
}

// Does not work! The output of Index must be a reference that is
// borrowed from self. Here the type Column is not a reference.
impl Index<usize> for TileMap {
    fn index(&self, x: usize) -> Column {
        assert!(x < MAP_WIDTH);
        Column { tilemap: self, x }
    }
}

impl<'a> Index<usize> for Column<'a> {
    fn index(&self, y: usize) -> &Tile {
        &self.tilemap.storage[y * MAP_WIDTH + self.x]
    }
}
```

Here is a working approach using `RefCast`.

```rust
#[derive(RefCast)]
#[repr(transparent)]
struct Strided([Tile]);

// Implement `tilemap[x][y]` as `tilemap[x..][y * MAP_WIDTH]`.
impl Index<usize> for TileMap {
    type Output = Strided;
    fn index(&self, x: usize) -> &Self::Output {
        assert!(x < MAP_WIDTH);
        Strided::ref_cast(&self.storage[x..])
    }
}

impl Index<usize> for Strided {
    type Output = Tile;
    fn index(&self, y: usize) -> &Self::Output {
        &self.0[y * MAP_WIDTH]
    }
}
```

<br>

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
