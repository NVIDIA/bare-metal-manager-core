use crate::{merge, patch, Patch};
use serde::Deserialize;
use serde_json::Value;
use std::fmt::Write;
use std::{fs, io};

#[derive(Debug, Deserialize)]
struct TestCase {
    comment: Option<String>,
    doc: Value,
    patch: Value,
    expected: Option<Value>,
    error: Option<String>,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    merge: bool,
}

fn run_case(doc: Value, patches: Value, merge_patch: bool) -> Result<Value, String> {
    let mut actual = doc.clone();
    if merge_patch {
        merge(&mut actual, &patches);
    } else {
        let patches: Patch = serde_json::from_value(patches).map_err(|e| e.to_string())?;

        // Patch and verify that in case of error document wasn't changed
        patch(&mut actual, &patches)
            .map_err(|e| {
                assert_eq!(
                    doc, actual,
                    "no changes should be made to the original document"
                );
                e
            })
            .map_err(|e| e.to_string())?;
    }
    Ok(actual)
}

pub fn run_specs(path: &str) {
    let file = fs::File::open(path).unwrap();
    let buf = io::BufReader::new(file);
    let cases: Vec<TestCase> = serde_json::from_reader(buf).unwrap();

    for (idx, tc) in cases.into_iter().enumerate() {
        print!("Running test case {}", idx);
        if let Some(comment) = tc.comment {
            print!(" ({})... ", comment);
        } else {
            print!("... ");
        }

        if tc.disabled {
            println!("disabled...");
            continue;
        }

        match run_case(tc.doc, tc.patch, tc.merge) {
            Ok(actual) => {
                if let Some(ref error) = tc.error {
                    println!("expected to fail with '{}'", error);
                    panic!("expected to fail, got document {:?}", actual);
                }
                println!();
                if let Some(expected) = tc.expected {
                    assert_eq!(expected, actual);
                }
            }
            Err(err) => {
                println!("failed with '{}'", err);
                tc.error.expect("patch expected to succeed");
            }
        }
    }
}
