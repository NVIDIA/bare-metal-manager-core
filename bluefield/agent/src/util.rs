#![allow(dead_code)]
// this stuff is used in tests and isn't actually dead

use std::fmt::Write;

use diff::Result;

pub fn compare_lines(left: &str, right: &str, strip_behavior: Option<StripType>) -> CompareResult {
    let (left, right) = match strip_behavior {
        None => (left, right),
        Some(_) => unreachable!(),
    };
    let results = diff::lines(left, right);
    let identical = results
        .iter()
        .all(|r| matches!(r, diff::Result::Both(_, _)));
    match identical {
        true => CompareResult::Identical,
        false => {
            let mut report = String::new();
            results.into_iter().for_each(|r| {
                let (col1, linecontent) = match r {
                    Result::Both(line, _) => (' ', line),
                    Result::Left(line) => ('-', line),
                    Result::Right(line) => ('+', line),
                };
                writeln!(&mut report, "{col1}{linecontent}").expect("can't write line to results?");
            });
            CompareResult::Different(report)
        }
    }
}

pub enum CompareResult {
    Identical,
    Different(String),
}

impl CompareResult {
    pub fn report(&self) -> &str {
        match self {
            CompareResult::Identical => "",
            CompareResult::Different(s) => s.as_str(),
        }
    }

    pub fn is_identical(&self) -> bool {
        matches!(self, CompareResult::Identical)
    }
}

pub enum StripType {}
