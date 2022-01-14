extern crate parse_zoneinfo;

use parse_zoneinfo::line::{Line, LineParser};
use parse_zoneinfo::table::TableBuilder;

// This function is needed until zoneinfo_parse handles comments correctly.
// Technically a '#' symbol could occur between double quotes and should be
// ignored in this case, however this never happens in the tz database as it
// stands.
fn strip_comments(mut line: String) -> String {
    line.find('#').map(|pos| line.truncate(pos));
    line
}

fn main() {
    let lines = std::fs::read_to_string("examples/asia")
        .unwrap()
        .lines()
        .map(|line| strip_comments(line.to_string()))
        .collect::<Vec<_>>();

    for _ in 0..100 {
        let parser = LineParser::new();
        let mut builder = TableBuilder::new();
        for line in &lines {
            match parser.parse_str(&line).unwrap() {
                Line::Zone(zone) => builder.add_zone_line(zone).unwrap(),
                Line::Continuation(cont) => builder.add_continuation_line(cont).unwrap(),
                Line::Rule(rule) => builder.add_rule_line(rule).unwrap(),
                Line::Link(link) => builder.add_link_line(link).unwrap(),
                Line::Space => {}
            }
        }
        let _table = builder.build();
    }
}
