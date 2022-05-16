#![allow(unused)]
extern crate rand;

mod util;

use super::*;
use serde_json::from_str;

#[test]
fn parse_from_value() {
    use PatchOperation::*;

    let json = json!([{"op": "add", "path": "/a/b", "value": 1}, {"op": "remove", "path": "/c"}]);
    let patch: Patch = from_value(json).unwrap();

    assert_eq!(
        patch,
        Patch(vec![
            Add(AddOperation {
                path: String::from("/a/b"),
                value: Value::from(1),
            }),
            Remove(RemoveOperation {
                path: String::from("/c"),
            }),
        ])
    );

    let _patch: Patch =
        from_str(r#"[{"op": "add", "path": "/a/b", "value": 1}, {"op": "remove", "path": "/c"}]"#)
            .unwrap();
}

#[test]
fn parse_from_string() {
    use PatchOperation::*;

    let patch: Patch =
        from_str(r#"[{"op": "add", "path": "/a/b", "value": 1}, {"op": "remove", "path": "/c"}]"#)
            .unwrap();

    assert_eq!(
        patch,
        Patch(vec![
            Add(AddOperation {
                path: String::from("/a/b"),
                value: Value::from(1),
            }),
            Remove(RemoveOperation {
                path: String::from("/c"),
            }),
        ])
    );
}

#[test]
fn serialize_patch() {
    let s = r#"[{"op":"add","path":"/a/b","value":1},{"op":"remove","path":"/c"}]"#;
    let patch: Patch = from_str(s).unwrap();

    let serialized = serde_json::to_string(&patch).unwrap();
    assert_eq!(serialized, s);
}

#[test]
fn tests() {
    util::run_specs("specs/tests.json");
}

#[test]
fn spec_tests() {
    util::run_specs("specs/spec_tests.json");
}

#[test]
fn revert_tests() {
    util::run_specs("specs/revert_tests.json");
}

#[test]
fn merge_tests() {
    util::run_specs("specs/merge_tests.json");
}
