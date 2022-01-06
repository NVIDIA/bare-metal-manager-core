extern crate parse_zoneinfo;
#[cfg(feature = "filter-by-regex")]
extern crate regex;

use std::collections::BTreeSet;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use parse_zoneinfo::line::{Line, LineParser};
use parse_zoneinfo::structure::{Child, Structure};
use parse_zoneinfo::table::{Table, TableBuilder};
use parse_zoneinfo::transitions::FixedTimespan;
use parse_zoneinfo::transitions::TableTransitions;

/// The name of the environment variable which possibly holds the filter regex.
const FILTER_ENV_VAR_NAME: &str = "CHRONO_TZ_TIMEZONE_FILTER";

// This function is needed until zoneinfo_parse handles comments correctly.
// Technically a '#' symbol could occur between double quotes and should be
// ignored in this case, however this never happens in the tz database as it
// stands.
fn strip_comments(mut line: String) -> String {
    if let Some(pos) = line.find('#') {
        line.truncate(pos);
    };
    line
}

// Generate a list of the time zone periods beyond the first that apply
// to this zone, as a string representation of a static slice.
fn format_rest(rest: Vec<(i64, FixedTimespan)>) -> String {
    let mut ret = "&[\n".to_string();
    for (start, FixedTimespan { utc_offset, dst_offset, name }) in rest {
        ret.push_str(&format!(
            "                    ({start}, FixedTimespan {{ \
             utc_offset: {utc}, dst_offset: {dst}, name: \"{name}\" \
             }}),\n",
            start = start,
            utc = utc_offset,
            dst = dst_offset,
            name = name,
        ));
    }
    ret.push_str("                ]");
    ret
}

// Convert all '/' to '__', all '+' to 'Plus' and '-' to 'Minus', unless
// it's a hyphen, in which case remove it. This is so the names can be used
// as rust identifiers.
fn convert_bad_chars(name: &str) -> String {
    let name = name.replace("/", "__").replace("+", "Plus");
    if let Some(pos) = name.find('-') {
        if name[pos + 1..].chars().next().map(char::is_numeric).unwrap_or(false) {
            name.replace("-", "Minus")
        } else {
            name.replace("-", "")
        }
    } else {
        name
    }
}

// The timezone file contains impls of `Timespans` for all timezones in the
// database. The `Wrap` wrapper in the `timezone_impl` module then implements
// TimeZone for any contained struct that implements `Timespans`.
fn write_timezone_file(timezone_file: &mut File, table: &Table) -> io::Result<()> {
    let zones = table.zonesets.keys().chain(table.links.keys()).collect::<BTreeSet<_>>();
    writeln!(timezone_file, "use core::fmt::{{self, Debug, Display, Formatter}};",)?;
    writeln!(timezone_file, "use core::str::FromStr;\n",)?;
    writeln!(
        timezone_file,
        "use ::timezone_impl::{{TimeSpans, FixedTimespanSet, FixedTimespan}};\n",
    )?;
    writeln!(
        timezone_file,
        "/// TimeZones built at compile time from the tz database
///
/// This implements [`chrono::TimeZone`] so that it may be used in and to
/// construct chrono's DateTime type. See the root module documentation
/// for details."
    )?;
    writeln!(timezone_file, "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\npub enum Tz {{")?;
    for zone in &zones {
        let zone_name = convert_bad_chars(zone);
        writeln!(
            timezone_file,
            "    /// {raw_zone_name}\n    {zone},",
            zone = zone_name,
            raw_zone_name = zone
        )?;
    }
    writeln!(timezone_file, "}}")?;

    let mut map = phf_codegen::Map::new();
    for zone in &zones {
        map.entry(zone, &format!("Tz::{}", convert_bad_chars(zone)));
    }
    writeln!(timezone_file, "static TIMEZONES: ::phf::Map<&'static str, Tz> = \n{};", map.build())?;

    #[cfg(feature = "case-insensitive")]
    {
        writeln!(timezone_file, "use uncased::UncasedStr;\n",)?;
        let mut map = phf_codegen::Map::new();
        for zone in &zones {
            map.entry(uncased::UncasedStr::new(zone), &format!("Tz::{}", convert_bad_chars(zone)));
        }
        writeln!(
            timezone_file,
            "static TIMEZONES_UNCASED: ::phf::Map<&'static uncased::UncasedStr, Tz> = \n{};",
            // FIXME(petrosagg): remove this once rust-phf/rust-phf#232 is released
            map.build().to_string().replace("::std::mem::transmute", "::core::mem::transmute")
        )?;
    }

    writeln!(
        timezone_file,
        "#[cfg(feature = \"std\")]
pub type ParseError = String;
#[cfg(not(feature = \"std\"))]
pub type ParseError = &'static str;

impl FromStr for Tz {{
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {{
        #[cfg(feature = \"std\")]
        return TIMEZONES.get(s).cloned().ok_or_else(|| format!(\"'{{}}' is not a valid timezone\", s));
        #[cfg(not(feature = \"std\"))]
        return TIMEZONES.get(s).cloned().ok_or(\"received invalid timezone\");
    }}
}}\n"
    )?;

    writeln!(
        timezone_file,
        "impl Tz {{
    pub fn name(self) -> &'static str {{
        match self {{"
    )?;
    for zone in &zones {
        let zone_name = convert_bad_chars(zone);
        writeln!(
            timezone_file,
            "            Tz::{zone} => \"{raw_zone_name}\",",
            zone = zone_name,
            raw_zone_name = zone
        )?;
    }
    writeln!(
        timezone_file,
        "        }}
    }}"
    )?;

    #[cfg(feature = "case-insensitive")]
    {
        writeln!(
            timezone_file,
            r#"
    #[cfg(feature = "case-insensitive")]
    /// Parses a timezone string in a case-insensitive way
    pub fn from_str_insensitive(s: &str) -> Result<Self, ParseError> {{
        #[cfg(feature = "std")]
        return TIMEZONES_UNCASED.get(s.into()).cloned().ok_or_else(|| format!("'{{}}' is not a valid timezone", s));
        #[cfg(not(feature = "std"))]
        return TIMEZONES_UNCASED.get(s.into()).cloned().ok_or("received invalid timezone");
    }}"#
        )?;
    }

    writeln!(timezone_file, "}}")?;

    writeln!(
        timezone_file,
        "impl Debug for Tz {{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {{
        f.write_str(self.name().as_ref())
    }}
}}\n"
    )?;
    writeln!(
        timezone_file,
        "impl Display for Tz {{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {{
        f.write_str(self.name().as_ref())
    }}
}}\n"
    )?;
    writeln!(
        timezone_file,
        "impl TimeSpans for Tz {{
    fn timespans(&self) -> FixedTimespanSet {{
        match *self {{"
    )?;
    for zone in &zones {
        let timespans = table.timespans(&zone).unwrap();
        let zone_name = convert_bad_chars(zone);
        writeln!(
            timezone_file,
            "            Tz::{zone} => {{
                const REST: &[(i64, FixedTimespan)] = {rest};
                FixedTimespanSet {{
                    first: FixedTimespan {{
                        utc_offset: {utc},
                        dst_offset: {dst},
                        name: \"{name}\",
                    }},
                    rest: REST
                }}
            }},\n",
            zone = zone_name,
            rest = format_rest(timespans.rest),
            utc = timespans.first.utc_offset,
            dst = timespans.first.dst_offset,
            name = timespans.first.name,
        )?;
    }
    write!(
        timezone_file,
        "         }}
    }}
}}\n"
    )?;
    write!(
        timezone_file,
        "/// An array of every known variant
///
/// Useful for iterating over known timezones:
///
/// ```
/// use chrono_tz::{{TZ_VARIANTS, Tz}};
/// assert!(TZ_VARIANTS.iter().any(|v| *v == Tz::UTC));
/// ```
pub static TZ_VARIANTS: [Tz; {num}] = [
",
        num = zones.len()
    )?;
    for zone in &zones {
        writeln!(timezone_file, "    Tz::{zone},", zone = convert_bad_chars(zone))?;
    }
    write!(timezone_file, "];")?;
    Ok(())
}

// Create a file containing nice-looking re-exports such as Europe::London
// instead of having to use chrono_tz::timezones::Europe__London
fn write_directory_file(directory_file: &mut File, table: &Table) -> io::Result<()> {
    // add the `loose' zone definitions first at the top of the file
    writeln!(directory_file, "use timezones::Tz;\n")?;
    let zones = table
        .zonesets
        .keys()
        .chain(table.links.keys())
        .filter(|zone| !zone.contains('/'))
        .collect::<BTreeSet<_>>();
    for zone in zones {
        let zone = convert_bad_chars(zone);
        writeln!(directory_file, "pub const {name} : Tz = Tz::{name};", name = zone)?;
    }
    writeln!(directory_file)?;

    // now add the `structured' zone names in submodules
    for entry in table.structure() {
        if entry.name.contains('/') {
            continue;
        }
        let module_name = convert_bad_chars(entry.name);
        writeln!(directory_file, "pub mod {name} {{", name = module_name)?;
        writeln!(directory_file, "    use timezones::Tz;\n",)?;
        for child in entry.children {
            match child {
                Child::Submodule(name) => {
                    let submodule_name = convert_bad_chars(name);
                    writeln!(directory_file, "    pub mod {name} {{", name = submodule_name)?;
                    writeln!(directory_file, "        use timezones::Tz;\n",)?;
                    let full_name = entry.name.to_string() + "/" + name;
                    for entry in table.structure() {
                        if entry.name == full_name {
                            for child in entry.children {
                                match child {
                                    Child::Submodule(_) => {
                                        panic!("Depth of > 3 nested submodules not implemented!")
                                    }
                                    Child::TimeZone(name) => {
                                        let converted_name = convert_bad_chars(name);
                                        writeln!(directory_file,
                                    "        pub const {name} : Tz = Tz::{module_name}__{submodule_name}__{name};",
                                            module_name = module_name,
                                            submodule_name = submodule_name,
                                            name = converted_name,
                                        )?;
                                    }
                                }
                            }
                        }
                    }
                    writeln!(directory_file, "    }}\n")?;
                }
                Child::TimeZone(name) => {
                    let name = convert_bad_chars(name);
                    writeln!(
                        directory_file,
                        "    pub const {name} : Tz = Tz::{module_name}__{name};",
                        module_name = module_name,
                        name = name
                    )?;
                }
            }
        }
        writeln!(directory_file, "}}\n")?;
    }
    Ok(())
}

/// Stub module because filter-by-regex feature is not enabled
#[cfg(not(feature = "filter-by-regex"))]
mod filter {
    /// stub function because filter-by-regex feature is not enabled
    pub(crate) fn maybe_filter_timezone_table(_table: &mut super::Table) {}
}

/// Module containing code supporting filter-by-regex feature
#[cfg(feature = "filter-by-regex")]
mod filter {
    use std::collections::HashSet;
    use std::env;

    use regex::Regex;

    use crate::{Table, FILTER_ENV_VAR_NAME};

    /// Filter `table` by applying [`FILTER_ENV_VAR_NAME`].
    pub(crate) fn maybe_filter_timezone_table(table: &mut Table) {
        if let Some(filter_regex) = get_filter_regex() {
            filter_timezone_table(table, filter_regex);
        }
    }

    /// Checks the `CHRONO_TZ_TIMEZONE_FILTER` environment variable.
    /// Converts it to a regex if set. Panics if the regex is not valid, as we want
    /// to fail the build if that happens.
    fn get_filter_regex() -> Option<Regex> {
        match env::var(FILTER_ENV_VAR_NAME) {
            Ok(val) => {
                let val = val.trim();
                if val.is_empty() {
                    return None;
                }
                match Regex::new(val) {
                    Ok(regex) => Some(regex),
                    Err(err) => panic!(
                        "The value '{:?}' for environment variable {} is not a valid regex, err={}",
                        val, FILTER_ENV_VAR_NAME, err
                    ),
                }
            }
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(s)) => panic!(
                "The value '{:?}' for environment variable {} is not valid Unicode",
                s, FILTER_ENV_VAR_NAME
            ),
        }
    }

    /// Insert a new name in the list of names to keep. If the name has 3
    /// parts, then also insert the 2-part prefix. If we don't do this we will lose
    /// half of Indiana in `directory.rs`. But we *don't* want to keep one-part names,
    /// otherwise we will inevitably end up with 'America' and include too much as
    /// a consequence.
    fn insert_keep_entry(keep: &mut HashSet<String>, new_value: &str) {
        let mut parts = new_value.split('/');
        if let (Some(p1), Some(p2), Some(_), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        {
            keep.insert(format!("{}/{}", p1, p2));
        }

        keep.insert(new_value.to_string());
    }

    /// Filter `table` by applying `filter_regex`.
    fn filter_timezone_table(table: &mut Table, filter_regex: Regex) {
        // Compute the transitive closure of things to keep.
        // Doing this, instead of just filtering `zonesets` and `links` by the
        // regiex, helps to keep the `structure()` intact.
        let mut keep = HashSet::new();
        for (k, v) in &table.links {
            if filter_regex.is_match(k) {
                insert_keep_entry(&mut keep, k);
            }
            if filter_regex.is_match(v) {
                insert_keep_entry(&mut keep, v);
            }
        }

        let mut n = 0;
        loop {
            let len = keep.len();

            for (k, v) in &table.links {
                if keep.contains(k) && !keep.contains(v) {
                    insert_keep_entry(&mut keep, v);
                }
                if keep.contains(v) && !keep.contains(k) {
                    insert_keep_entry(&mut keep, k);
                }
            }

            if keep.len() == len {
                break;
            }

            n += 1;
            if n == 50 {
                println!("cargo:warning=Recursion limit reached while building filter list");
                break;
            }
        }

        // Actually do the filtering.
        table.links.retain(|k, v| keep.contains(k) || keep.contains(v));

        table
            .zonesets
            .retain(|k, _| filter_regex.is_match(&k) || keep.iter().any(|s| k.starts_with(s)));
    }
}

pub fn main() {
    println!("cargo:rerun-if-env-changed={}", FILTER_ENV_VAR_NAME);

    let parser = LineParser::new();
    let mut table = TableBuilder::new();

    let tzfiles = [
        "tz/africa",
        "tz/antarctica",
        "tz/asia",
        "tz/australasia",
        "tz/backward",
        "tz/etcetera",
        "tz/europe",
        "tz/northamerica",
        "tz/southamerica",
    ];

    let lines = tzfiles
        .iter()
        .map(Path::new)
        .map(|p| {
            Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| String::new())).join(p)
        })
        .map(|path| {
            File::open(&path).unwrap_or_else(|e| panic!("cannot open {}: {}", path.display(), e))
        })
        .map(BufReader::new)
        .flat_map(BufRead::lines)
        .map(Result::unwrap)
        .map(strip_comments);

    for line in lines {
        match parser.parse_str(&line).unwrap() {
            Line::Zone(zone) => table.add_zone_line(zone).unwrap(),
            Line::Continuation(cont) => table.add_continuation_line(cont).unwrap(),
            Line::Rule(rule) => table.add_rule_line(rule).unwrap(),
            Line::Link(link) => table.add_link_line(link).unwrap(),
            Line::Space => {}
        }
    }

    let mut table = table.build();
    filter::maybe_filter_timezone_table(&mut table);

    let timezone_path = Path::new(&env::var("OUT_DIR").unwrap()).join("timezones.rs");
    let mut timezone_file = File::create(&timezone_path).unwrap();
    write_timezone_file(&mut timezone_file, &table).unwrap();

    let directory_path = Path::new(&env::var("OUT_DIR").unwrap()).join("directory.rs");
    let mut directory_file = File::create(&directory_path).unwrap();
    write_directory_file(&mut directory_file, &table).unwrap();
}
