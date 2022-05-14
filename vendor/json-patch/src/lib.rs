//! A [JSON Patch (RFC 6902)](https://tools.ietf.org/html/rfc6902) and
//! [JSON Merge Patch (RFC 7396)](https://tools.ietf.org/html/rfc7396) implementation for Rust.
//!
//! # Usage
//!
//! Add this to your *Cargo.toml*:
//! ```toml
//! [dependencies]
//! json-patch = "*"
//! ```
//!
//! # Examples
//! Create and patch document using JSON Patch:
//!
//! ```rust
//! #[macro_use]
//! extern crate serde_json;
//! extern crate json_patch;
//!
//! use json_patch::patch;
//! use serde_json::from_str;
//!
//! # pub fn main() {
//! let mut doc = json!([
//!     { "name": "Andrew" },
//!     { "name": "Maxim" }
//! ]);
//!
//! let p = from_str(r#"[
//!   { "op": "test", "path": "/0/name", "value": "Andrew" },
//!   { "op": "add", "path": "/0/happy", "value": true }
//! ]"#).unwrap();
//!
//! patch(&mut doc, &p).unwrap();
//! assert_eq!(doc, json!([
//!   { "name": "Andrew", "happy": true },
//!   { "name": "Maxim" }
//! ]));
//!
//! # }
//! ```
//!
//! Create and patch document using JSON Merge Patch:
//!
//! ```rust
//! #[macro_use]
//! extern crate serde_json;
//! extern crate json_patch;
//!
//! use json_patch::merge;
//!
//! # pub fn main() {
//! let mut doc = json!({
//!   "title": "Goodbye!",
//!   "author" : {
//!     "givenName" : "John",
//!     "familyName" : "Doe"
//!   },
//!   "tags":[ "example", "sample" ],
//!   "content": "This will be unchanged"
//! });
//!
//! let patch = json!({
//!   "title": "Hello!",
//!   "phoneNumber": "+01-123-456-7890",
//!   "author": {
//!     "familyName": null
//!   },
//!   "tags": [ "example" ]
//! });
//!
//! merge(&mut doc, &patch);
//! assert_eq!(doc, json!({
//!   "title": "Hello!",
//!   "author" : {
//!     "givenName" : "John"
//!   },
//!   "tags": [ "example" ],
//!   "content": "This will be unchanged",
//!   "phoneNumber": "+01-123-456-7890"
//! }));
//! # }
//! ```
#![deny(warnings)]
#![warn(missing_docs)]
#[cfg_attr(test, macro_use)]
extern crate serde_json;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::error::Error;
use std::{fmt, mem};

/// Representation of JSON Patch (list of patch operations)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Patch(pub Vec<PatchOperation>);

/// JSON Patch 'add' operation representation
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AddOperation {
    /// JSON-Pointer value [RFC6901](https://tools.ietf.org/html/rfc6901) that references a location
    /// within the target document where the operation is performed.
    pub path: String,
    /// Value to add to the target location.
    pub value: Value,
}

/// JSON Patch 'remove' operation representation
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct RemoveOperation {
    /// JSON-Pointer value [RFC6901](https://tools.ietf.org/html/rfc6901) that references a location
    /// within the target document where the operation is performed.
    pub path: String,
}

/// JSON Patch 'replace' operation representation
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ReplaceOperation {
    /// JSON-Pointer value [RFC6901](https://tools.ietf.org/html/rfc6901) that references a location
    /// within the target document where the operation is performed.
    pub path: String,
    /// Value to replace with.
    pub value: Value,
}

/// JSON Patch 'move' operation representation
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct MoveOperation {
    /// JSON-Pointer value [RFC6901](https://tools.ietf.org/html/rfc6901) that references a location
    /// to move value from.
    pub from: String,
    /// JSON-Pointer value [RFC6901](https://tools.ietf.org/html/rfc6901) that references a location
    /// within the target document where the operation is performed.
    pub path: String,
}

/// JSON Patch 'copy' operation representation
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct CopyOperation {
    /// JSON-Pointer value [RFC6901](https://tools.ietf.org/html/rfc6901) that references a location
    /// to copy value from.
    pub from: String,
    /// JSON-Pointer value [RFC6901](https://tools.ietf.org/html/rfc6901) that references a location
    /// within the target document where the operation is performed.
    pub path: String,
}

/// JSON Patch 'test' operation representation
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TestOperation {
    /// JSON-Pointer value [RFC6901](https://tools.ietf.org/html/rfc6901) that references a location
    /// within the target document where the operation is performed.
    pub path: String,
    /// Value to test against.
    pub value: Value,
}

/// JSON Patch single patch operation
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "op")]
#[serde(rename_all = "lowercase")]
pub enum PatchOperation {
    /// 'add' operation
    Add(AddOperation),
    /// 'remove' operation
    Remove(RemoveOperation),
    /// 'replace' operation
    Replace(ReplaceOperation),
    /// 'move' operation
    Move(MoveOperation),
    /// 'copy' operation
    Copy(CopyOperation),
    /// 'test' operation
    Test(TestOperation),
}

/// This type represents all possible errors that can occur when applying JSON patch
#[derive(Debug)]
pub enum PatchError {
    /// One of the pointers in the patch is invalid
    InvalidPointer,

    /// 'test' operation failed
    TestFailed,
}

impl Error for PatchError {
    fn description(&self) -> &str {
        match *self {
            PatchError::InvalidPointer => "invalid pointer",
            PatchError::TestFailed => "test failed",
        }
    }
}

impl fmt::Display for PatchError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.description().fmt(fmt)
    }
}

fn parse_index(str: &str, len: usize) -> Result<usize, PatchError> {
    // RFC 6901 prohibits leading zeroes in index
    if str.starts_with('0') && str.len() != 1 {
        return Err(PatchError::InvalidPointer);
    }
    match str.parse::<usize>() {
        Ok(idx) if idx < len => Ok(idx),
        _ => Err(PatchError::InvalidPointer),
    }
}

fn split_pointer(pointer: &str) -> Result<(&str, String), PatchError> {
    pointer
        .rfind('/')
        .ok_or(PatchError::InvalidPointer)
        .map(|idx| {
            (
                &pointer[0..idx],
                pointer[idx + 1..].replace("~1", "/").replace("~0", "~"),
            )
        })
}

fn add(doc: &mut Value, path: &str, value: Value) -> Result<Option<Value>, PatchError> {
    if path == "" {
        return Ok(Some(mem::replace(doc, value)));
    }

    let (parent, last) = split_pointer(path)?;
    let parent = doc.pointer_mut(parent).ok_or(PatchError::InvalidPointer)?;

    match *parent {
        Value::Object(ref mut obj) => Ok(obj.insert(last, value)),
        Value::Array(ref mut arr) if last == "-" => {
            arr.push(value);
            Ok(None)
        }
        Value::Array(ref mut arr) => {
            let idx = parse_index(last.as_str(), arr.len() + 1)?;
            arr.insert(idx, value);
            Ok(None)
        }
        _ => Err(PatchError::InvalidPointer),
    }
}

fn remove(doc: &mut Value, path: &str, allow_last: bool) -> Result<Value, PatchError> {
    let (parent, last) = split_pointer(path)?;
    let parent = doc.pointer_mut(parent).ok_or(PatchError::InvalidPointer)?;

    match *parent {
        Value::Object(ref mut obj) => match obj.remove(last.as_str()) {
            None => Err(PatchError::InvalidPointer),
            Some(val) => Ok(val),
        },
        Value::Array(ref mut arr) if allow_last && last == "-" => Ok(arr.pop().unwrap()),
        Value::Array(ref mut arr) => {
            let idx = parse_index(last.as_str(), arr.len())?;
            Ok(arr.remove(idx))
        }
        _ => Err(PatchError::InvalidPointer),
    }
}

fn replace(doc: &mut Value, path: &str, value: Value) -> Result<Value, PatchError> {
    let target = doc.pointer_mut(path).ok_or(PatchError::InvalidPointer)?;
    Ok(mem::replace(target, value))
}

fn mov(
    doc: &mut Value,
    from: &str,
    path: &str,
    allow_last: bool,
) -> Result<Option<Value>, PatchError> {
    // Check we are not moving inside own child
    if path.starts_with(from) && path[from.len()..].starts_with('/') {
        return Err(PatchError::InvalidPointer);
    }
    let val = remove(doc, from, allow_last)?;
    add(doc, path, val)
}

fn copy(doc: &mut Value, from: &str, path: &str) -> Result<Option<Value>, PatchError> {
    let source = doc.pointer(from).ok_or(PatchError::InvalidPointer)?.clone();
    add(doc, path, source)
}

fn test(doc: &Value, path: &str, expected: &Value) -> Result<(), PatchError> {
    let target = doc.pointer(path).ok_or(PatchError::InvalidPointer)?;
    if *target == *expected {
        Ok(())
    } else {
        Err(PatchError::TestFailed)
    }
}

/// Create JSON Patch from JSON Value
/// # Examples
///
/// Create patch from `serde_json::Value`:
///
/// ```rust
/// #[macro_use]
/// extern crate serde_json;
/// extern crate json_patch;
///
/// use json_patch::{Patch, from_value};
///
/// # pub fn main() {
/// let patch_value = json!([
///   { "op": "test", "path": "/0/name", "value": "Andrew" },
///   { "op": "add", "path": "/0/happy", "value": true }
/// ]);
/// let patch: Patch = from_value(patch_value).unwrap();
/// # }
/// ```
///
/// Create patch from string:
///
/// ```rust
/// #[macro_use]
/// extern crate serde_json;
/// extern crate json_patch;
///
/// use json_patch::Patch;
/// use serde_json::from_str;
///
/// # pub fn main() {
/// let patch_str = r#"[
///   { "op": "test", "path": "/0/name", "value": "Andrew" },
///   { "op": "add", "path": "/0/happy", "value": true }
/// ]"#;
/// let patch: Patch = from_str(patch_str).unwrap();
/// # }
/// ```
pub fn from_value(value: Value) -> Result<Patch, serde_json::Error> {
    let patch = serde_json::from_value::<Vec<PatchOperation>>(value)?;
    Ok(Patch(patch))
}

/// Patch provided JSON document (given as `serde_json::Value`) in-place. If any of the patch is
/// failed, all previous operations are reverted. In case of internal error resulting in panic,
/// document might be left in inconsistent state.
///
/// # Example
/// Create and patch document:
///
/// ```rust
/// #[macro_use]
/// extern crate serde_json;
/// extern crate json_patch;
///
/// use json_patch::patch;
/// use serde_json::from_str;
///
/// # pub fn main() {
/// let mut doc = json!([
///     { "name": "Andrew" },
///     { "name": "Maxim" }
/// ]);
///
/// let p = from_str(r#"[
///   { "op": "test", "path": "/0/name", "value": "Andrew" },
///   { "op": "add", "path": "/0/happy", "value": true }
/// ]"#).unwrap();
///
/// patch(&mut doc, &p).unwrap();
/// assert_eq!(doc, json!([
///   { "name": "Andrew", "happy": true },
///   { "name": "Maxim" }
/// ]));
///
/// # }
/// ```
pub fn patch(doc: &mut Value, patch: &Patch) -> Result<(), PatchError> {
    apply_patches(doc, &patch.0)
}

// Apply patches while tracking all the changes being made so they can be reverted back in case
// subsequent patches fail. Uses stack recursion to keep the state.
fn apply_patches(doc: &mut Value, patches: &[PatchOperation]) -> Result<(), PatchError> {
    let (patch, tail) = match patches.split_first() {
        None => return Ok(()),
        Some((patch, tail)) => (patch, tail),
    };

    match *patch {
        PatchOperation::Add(ref op) => {
            let prev = add(doc, op.path.as_str(), op.value.clone())?;
            apply_patches(doc, tail).map_err(move |e| {
                match prev {
                    None => remove(doc, op.path.as_str(), true).unwrap(),
                    Some(v) => add(doc, op.path.as_str(), v).unwrap().unwrap(),
                };
                e
            })
        }
        PatchOperation::Remove(ref op) => {
            let prev = remove(doc, op.path.as_str(), false)?;
            apply_patches(doc, tail).map_err(move |e| {
                assert!(add(doc, op.path.as_str(), prev).unwrap().is_none());
                e
            })
        }
        PatchOperation::Replace(ref op) => {
            let prev = replace(doc, op.path.as_str(), op.value.clone())?;
            apply_patches(doc, tail).map_err(move |e| {
                replace(doc, op.path.as_str(), prev).unwrap();
                e
            })
        }
        PatchOperation::Move(ref op) => {
            let prev = mov(doc, op.from.as_str(), op.path.as_str(), false)?;
            apply_patches(doc, tail).map_err(move |e| {
                mov(doc, op.path.as_str(), op.from.as_str(), true).unwrap();
                if let Some(prev) = prev {
                    assert!(add(doc, op.path.as_str(), prev).unwrap().is_none());
                }
                e
            })
        }
        PatchOperation::Copy(ref op) => {
            let prev = copy(doc, op.from.as_str(), op.path.as_str())?;
            apply_patches(doc, tail).map_err(move |e| {
                match prev {
                    None => remove(doc, op.path.as_str(), true).unwrap(),
                    Some(v) => add(doc, op.path.as_str(), v).unwrap().unwrap(),
                };
                e
            })
        }
        PatchOperation::Test(ref op) => {
            test(doc, op.path.as_str(), &op.value)?;
            apply_patches(doc, tail)
        }
    }
}

/// Patch provided JSON document (given as `serde_json::Value`) in place.
/// Operations are applied in unsafe manner. If any of the operations fails, all previous
/// operations are not reverted.
pub fn patch_unsafe(doc: &mut Value, patch: &Patch) -> Result<(), PatchError> {
    for op in &patch.0 {
        match *op {
            PatchOperation::Add(ref op) => {
                add(doc, op.path.as_str(), op.value.clone())?;
            }
            PatchOperation::Remove(ref op) => {
                remove(doc, op.path.as_str(), false)?;
            }
            PatchOperation::Replace(ref op) => {
                replace(doc, op.path.as_str(), op.value.clone())?;
            }
            PatchOperation::Move(ref op) => {
                mov(doc, op.from.as_str(), op.path.as_str(), false)?;
            }
            PatchOperation::Copy(ref op) => {
                copy(doc, op.from.as_str(), op.path.as_str())?;
            }
            PatchOperation::Test(ref op) => {
                test(doc, op.path.as_str(), &op.value)?;
            }
        };
    }
    Ok(())
}

/// Patch provided JSON document (given as `serde_json::Value`) in place with JSON Merge Patch
/// (RFC 7396).
///
/// # Example
/// Create and patch document:
///
/// ```rust
/// #[macro_use]
/// extern crate serde_json;
/// extern crate json_patch;
///
/// use json_patch::merge;
///
/// # pub fn main() {
/// let mut doc = json!({
///   "title": "Goodbye!",
///   "author" : {
///     "givenName" : "John",
///     "familyName" : "Doe"
///   },
///   "tags":[ "example", "sample" ],
///   "content": "This will be unchanged"
/// });
///
/// let patch = json!({
///   "title": "Hello!",
///   "phoneNumber": "+01-123-456-7890",
///   "author": {
///     "familyName": null
///   },
///   "tags": [ "example" ]
/// });
///
/// merge(&mut doc, &patch);
/// assert_eq!(doc, json!({
///   "title": "Hello!",
///   "author" : {
///     "givenName" : "John"
///   },
///   "tags": [ "example" ],
///   "content": "This will be unchanged",
///   "phoneNumber": "+01-123-456-7890"
/// }));
/// # }
/// ```
pub fn merge(doc: &mut Value, patch: &Value) {
    if !patch.is_object() {
        *doc = patch.clone();
        return;
    }

    if !doc.is_object() {
        *doc = Value::Object(Map::new());
    }
    let map = doc.as_object_mut().unwrap();
    for (key, value) in patch.as_object().unwrap() {
        if value.is_null() {
            map.remove(key.as_str());
        } else {
            merge(map.entry(key.as_str()).or_insert(Value::Null), value);
        }
    }
}

#[cfg(feature = "diff")]
mod diff;

#[cfg(feature = "diff")]
pub use self::diff::diff;

#[cfg(test)]
mod tests;
