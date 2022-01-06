extern crate clap;
extern crate patricia_tree;

use clap::{App, Arg};
use patricia_tree::PatriciaSet;
use std::collections::{BTreeSet, HashSet};
use std::io::BufRead;

fn main() {
    let matches = App::new("insert_lines")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::with_name("KIND")
                .long("kind")
                .takes_value(true)
                .possible_values(&["patricia", "hash", "btree", "count"])
                .default_value("patricia"),
        )
        .get_matches();

    match matches.value_of("KIND").unwrap() {
        "patricia" => {
            let mut set = PatriciaSet::new();
            each_line(|line| {
                set.insert(line);
            });
            println!("# LINES: {}", set.len());
        }
        "hash" => {
            let mut set = HashSet::new();
            each_line(|line| {
                set.insert(line);
            });
            println!("# LINES: {}", set.len());
        }
        "btree" => {
            let mut set = BTreeSet::new();
            each_line(|line| {
                set.insert(line);
            });
            println!("# LINES: {}", set.len());
        }
        "count" => {
            let mut count = 0;
            each_line(|_| {
                count += 1;
            });
            println!("# LINES: {}", count);
        }
        _ => unreachable!(),
    }
}

fn each_line<F>(mut f: F)
where
    F: FnMut(String),
{
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        f(line.unwrap());
    }
}
