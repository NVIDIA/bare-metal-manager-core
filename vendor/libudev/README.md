# Libudev
This crate provides a safe wrapper around the native `libudev` library.

* [Documentation](http://dcuddeback.github.io/libudev-rs/libudev/)

## Dependencies
In order to use the `libudev` crate, you must have a Linux system with the `libudev` library
installed where it can be found by `pkg-config`. To install `libudev` on Debian-based Linux
distributions, execute the following command:

```
sudo apt-get install libudev-dev
```

`libudev` is a Linux-specific package. It is not available for Windows, OS X, or other operating
systems.

### Cross-Compiling
The `libudev` crate can be used when cross-compiling to a foreign target. Details on how to
cross-compile `libudev` are explained in the [`libudev-sys` crate's
README](https://github.com/dcuddeback/libudev-sys#cross-compiling).

## Usage
Add `libudev` as a dependency in `Cargo.toml`:

```toml
[dependencies]
libudev = "0.3"
```

If you plan to support operating systems other than Linux, you'll need to add `libudev` as a
target-specific dependency:

```toml
[target.x86_64-unknown-linux-gnu.dependencies]
libudev = "0.3"
```

Import the `libudev` crate. The starting point for nearly all `libudev` functionality is to create a
context object.

```rust
extern crate libudev;

fn main() {
    let context = libudev::Context::new().unwrap();
    let mut enumerator = libudev::Enumerator::new(&context).unwrap();

    enumerator.match_subsystem("tty").unwrap();

    for device in enumerator.scan_devices().unwrap() {
        println!("found device: {:?}", device.syspath());
    }
}
```

## License
Copyright © 2015 David Cuddeback

Distributed under the [MIT License](LICENSE).
