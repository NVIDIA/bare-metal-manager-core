# Change Log

## 0.3.0 (2020-01-17)

This release changes the resource management strategy. Tracking lifetimes of dependent resources
makes for a less-ergonomic API. That has been replaced with reference-counting. There are no known
backwards-compatibility issues with this change, so existing code should not have to be updated for
compatibility with reference-counting.

There are, however, some breaking changes to the API that are unrelated to the changes in resource
management:

1. `Context::device_from_syspath()` has been moved to `Device::from_syspath()`. Upgrading involves a
   search-and-replace. Anywhere you have the following code:

   ```rust
   context.device_from_syspath(path);
   ```

   should be replaced with:

   ```rust
   Device::from_syspath(&context, path);
   ```

2. Several methods on `Device` changed their return type to account for the possibility of the C
   library returning `NULL` pointers:

   * `Device::syspath()` returns `Option<&Path>` instead of `&Path`.
   * `Device::devpath()` returns `Option<&OsStr>` instead of `&OsStr`.
   * `Device::subsystem()` returns `Option<&OsStr>` instead of `&OsStr`.
   * `Device::sysname()` returns `Option<&OsStr>` instead of `&OsStr`.

   Client code will have to decide how to handle a `None` return value.

### Added
* Implemented `Clone` for `Context`.

### Fixed
* Fixed several issues related to lifetimes.
* Handled possible `NULL` return from `udev_device_get_syspath()`, `udev_device_get_devpath()`,
  `udev_device_get_subsystem()`, and `udev_device_get_sysname()`.
* Reduced memory footprint of several types to a single pointer.
* Reduced unnecessary memory allocations when iterating devices and setting up a monitor.

### Changed
* Replaced explicit lifetimes with reference counting.
* Moved `Context::device_from_syspath()` to `Device::from_syspath()`.
* Changed return type of `Device::syspath()`, `Device::devpath()`, `Device::subsystem()`, and
  `Device::sysname()` to `Option<...>`.


## 0.2.0 (2016-04-16)

### Added
* Added `Device::parent()`.

### Changed
* Replaced `c_int` error code with `std::io::ErrorKind`.
* Minimum supported version of Rust is now 1.4.0.


## 0.1.2 (2015-11-04)

### Changed
* Upgraded libc dependency to v0.2.


## 0.1.1 (2015-10-02)

### Added
* Added `Monitor`.
* Wrote documentation.

## 0.1.0 (2015-05-07)

### Changed
* Bumped `libudev-sys` dependency to v0.1.1, which allows `libudev` to compile on 1.0.0-beta and
  presumably the imminent 1.0.0 release.


## 0.0.2 (2015-04-14)

### Changed
* Removed dependencies on unstable features:
  * `#![feature(libc)]`: replaced with `libc` crate
  * `#1[feature(std_misc)]`: replaced `AsOsStr` with `AsRef<OsStr>`
  * `#![feature(unsafe_destructor)]`: stabilized


## 0.0.1 (2015-04-04)
Initial release
