/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Generates the `docs/manuals/nico-admin-cli` markdown reference from the live clap command tree.
//!
//! The per-command pages are derived from the same man pages the
//! `generate-man` subcommand produces: we render every command's roff man page
//! with `clap_mangen`, convert each to GitHub-flavored markdown with `pandoc`,
//! and reorganize them into one directory per top-level command. Using the man
//! pages (rather than hand-walking clap's `about`/`after_long_help`) is what
//! gives each page its full SYNOPSIS and per-flag OPTIONS detail.
//!
//! Layout: `commands/<command>/<command>.md` is the base page for a top-level
//! command, and each (flattened) descendant gets `commands/<command>/<command>-<sub>.md`
//! beside it, cross-linked via a breadcrumb and a Subcommands table. The four
//! domain index pages (Hardware/Network/Tenant/Admin) are written from
//! [`crate::cfg::cli_options::domain_for_command`]. Hand-authored pages
//! (`README.md`, `workflows.md`, `setup.md`, `rest-cli-parity.md`) are not
//! touched — operator workflows are editorial and cannot be machine-generated.

use std::fmt::Write as _;
use std::path::Path;

use clap::{Command, CommandFactory};

use crate::cfg::cli_options::{CliDomain, CliOptions, domain_for_command};
use crate::errors::{CarbideCliError, CarbideCliResult};

const BIN: &str = "nico-admin-cli";
const DOMAINS: [CliDomain; 4] = [
    CliDomain::Hardware,
    CliDomain::Network,
    CliDomain::Tenant,
    CliDomain::Admin,
];

pub fn generate(out_dir: &Path) -> CarbideCliResult<()> {
    let root = CliOptions::command().name(BIN);

    // Render every command's roff man page into a scratch directory. clap_mangen
    // names each file by the full command path joined with '-' (e.g.
    // `nico-admin-cli-vpc-show.1`), which we reconstruct per node below.
    let man_dir = tempfile::Builder::new()
        .prefix("nico-admin-cli-cli-docs-man-")
        .tempdir()?;
    clap_mangen::generate_to(root.clone(), man_dir.path())?;

    // One directory per top-level command, holding that command's page plus a
    // page for each (flattened) descendant. Rebuilt from scratch so a renamed or
    // removed command can't leave a stale page behind.
    let commands_dir = out_dir.join("commands");
    let _ = std::fs::remove_dir_all(&commands_dir);
    std::fs::create_dir_all(&commands_dir)?;

    // (name, one-line description, domain) for every visible top-level command,
    // used to build the domain index pages.
    let mut top_level: Vec<(String, String, CliDomain)> = Vec::new();

    for sub in root.get_subcommands() {
        if sub.is_hide_set() || sub.get_name() == "help" {
            continue;
        }
        let name = sub.get_name().to_string();
        let about = first_line(&styled(sub.get_about()));
        let domain = domain_for_command(&name).ok_or_else(|| {
            CarbideCliError::GenericError(format!(
                "command `{name}` has no CLI-docs domain; add it to \
                 crates/admin-cli/cli_domains.yaml"
            ))
        })?;

        let dir = commands_dir.join(&name);
        std::fs::create_dir_all(&dir)?;
        render_node(
            sub,
            vec![BIN.to_string(), name.clone()],
            domain,
            man_dir.path(),
            &dir,
        )?;

        top_level.push((name, about, domain));
    }

    top_level.sort_by(|a, b| a.0.cmp(&b.0));

    for domain in DOMAINS {
        let rows: Vec<&(String, String, CliDomain)> =
            top_level.iter().filter(|c| c.2 == domain).collect();
        std::fs::write(
            out_dir.join(format!("{}.md", slug(domain))),
            render_domain_index(domain, &rows),
        )?;
    }

    Ok(())
}

/// Writes the markdown page for `cmd` (whose full path from the binary is
/// `path`, e.g. `["nico-admin-cli", "vpc", "show"]`) and recurses into its
/// visible subcommands. Every page for one top-level command lives flat in
/// `dir`, named by the path below the binary joined with '-' (so `vpc show`
/// becomes `vpc-show.md`).
fn render_node(
    cmd: &Command,
    path: Vec<String>,
    domain: CliDomain,
    man_dir: &Path,
    dir: &Path,
) -> CarbideCliResult<()> {
    // The man page body, minus the sections we re-render ourselves: SUBCOMMANDS
    // (we emit a linked table) and EXTRA (the after_long_help examples, which
    // roff mangles — we re-render them from the clap command instead).
    let man_file = man_dir.join(format!("{}.1", path.join("-")));
    let body = strip_sections(&man_to_markdown(&man_file)?, &["SUBCOMMANDS", "EXTRA"]);

    let children: Vec<&Command> = cmd
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .collect();

    std::fs::write(
        dir.join(format!("{}.md", stem(&path))),
        render_command_page(cmd, &path, domain, &body, &children),
    )?;

    for child in &children {
        let mut child_path = path.clone();
        child_path.push(child.get_name().to_string());
        render_node(child, child_path, domain, man_dir, dir)?;
    }
    Ok(())
}

fn render_command_page(
    cmd: &Command,
    path: &[String],
    domain: CliDomain,
    body: &str,
    children: &[&Command],
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# `{}`\n", path.join(" "));
    let _ = writeln!(s, "{}\n", breadcrumb(path, domain));

    // SYNOPSIS / DESCRIPTION / OPTIONS lifted from the man page.
    let _ = writeln!(s, "{}\n", body.trim_end());

    if let Some(examples) = example_commands(cmd) {
        let _ = writeln!(s, "## Examples\n");
        let _ = writeln!(s, "```sh\n{examples}\n```\n");
    }

    if !children.is_empty() {
        let _ = writeln!(s, "## Subcommands\n");
        let _ = writeln!(s, "| Subcommand | Description |");
        let _ = writeln!(s, "|---|---|");
        // Children live beside this page; their stem extends this command's.
        let prefix = stem(path);
        for child in children {
            let child_name = child.get_name();
            let _ = writeln!(
                s,
                "| [`{child_name}`](./{prefix}-{child_name}.md) | {} |",
                first_line(&styled(child.get_about()))
            );
        }
        let _ = writeln!(s);
    }

    let _ = writeln!(s, "---\n");
    let _ = writeln!(
        s,
        "**See also:** [{} commands](../../{}.md) · [CLI reference index](../../README.md)",
        domain.title(),
        slug(domain),
    );
    s
}

fn render_domain_index(domain: CliDomain, rows: &[&(String, String, CliDomain)]) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# CLI reference — {}\n", domain.title());
    let _ = writeln!(s, "{}\n", intro(domain));
    let _ = writeln!(
        s,
        "For global flags and setup, see [the overview](./README.md) and \
         [`setup.md`](./setup.md). For task-oriented sequences see \
         [`workflows.md`](./workflows.md).\n"
    );
    let _ = writeln!(s, "| Command | Description |");
    let _ = writeln!(s, "|---|---|");
    for (name, about, _) in rows {
        let about = if about.is_empty() {
            String::new()
        } else if about.ends_with('.') {
            about.clone()
        } else {
            format!("{about}.")
        };
        let _ = writeln!(s, "| [`{name}`](./commands/{name}/{name}.md) | {about} |");
    }
    s
}

// ---- helpers ----

/// The page stem for a command path: the path below the binary joined with '-'
/// (`["nico-admin-cli", "vpc", "show"]` -> `"vpc-show"`). Both the file name
/// and the in-directory links use this.
fn stem(path: &[String]) -> String {
    path[1..].join("-")
}

/// A one-line navigation trail: the domain index, then each ancestor command as
/// a link, then the current command in bold.
fn breadcrumb(path: &[String], domain: CliDomain) -> String {
    let mut parts = vec![format!(
        "[{} commands](../../{}.md)",
        domain.title(),
        slug(domain)
    )];
    // Ancestors are everything between the binary and this command; each links
    // to its own page (which shares this directory).
    for depth in 2..path.len() {
        let ancestor = &path[depth - 1];
        let ancestor_stem = path[1..depth].join("-");
        parts.push(format!("[{ancestor}](./{ancestor_stem}.md)"));
    }
    parts.push(format!(
        "**{}**",
        path.last()
            .expect("a command path always has at least the binary")
    ));
    format!("_{}_", parts.join(" › "))
}

/// Removes the named top-level (`## `) sections from pandoc's markdown, heading
/// included, up to the next `## ` heading or end of document. Matching is
/// case-insensitive on the section title (man sections are single words like
/// `SUBCOMMANDS`).
fn strip_sections(md: &str, names: &[&str]) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in md.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            skipping = names.iter().any(|n| heading.trim().eq_ignore_ascii_case(n));
            if skipping {
                continue;
            }
        }
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Converts a roff man page to GitHub-flavored markdown via pandoc, demoting the
/// man page's `# NAME`/`# OPTIONS`/… sections to `## ` so each generated page
/// can own the `# ` title (the full command invocation).
fn man_to_markdown(man_file: &Path) -> CarbideCliResult<String> {
    let roff = std::fs::read_to_string(man_file)?;
    let normalized_roff = normalize_roff_for_pandoc(&roff);
    let pandoc_input = tempfile::NamedTempFile::new()?;
    std::fs::write(pandoc_input.path(), normalized_roff)?;

    let mut pandoc = pandoc::new();
    pandoc.add_input(pandoc_input.path());
    pandoc.set_input_format(pandoc::InputFormat::Other("man".to_string()), Vec::new());
    pandoc.set_output_format(pandoc::OutputFormat::Other("gfm".to_string()), Vec::new());
    pandoc.add_option(pandoc::PandocOption::ShiftHeadingLevelBy(1));
    pandoc.set_output(pandoc::OutputKind::Pipe);

    match pandoc.execute() {
        Ok(pandoc::PandocOutput::ToBuffer(markdown)) => Ok(normalize_pandoc_markdown(&markdown)),
        Ok(_) => Err(CarbideCliError::GenericError(format!(
            "pandoc returned non-text output converting man page {}",
            man_file.display()
        ))),
        Err(err) => Err(CarbideCliError::GenericError(format!(
            "while converting man page {} to markdown with pandoc: {err}",
            man_file.display()
        ))),
    }
}

/// Expands the small subset of roff emitted by clap_mangen that pandoc's man
/// reader does not preserve when converting to GFM.
fn normalize_roff_for_pandoc(roff: &str) -> String {
    let roff = normalize_roff_apostrophes(roff);
    let mut normalized = String::with_capacity(roff.len());

    for line in roff.split_inclusive('\n') {
        let backticks = line.matches('`').count();
        if backticks >= 2 && backticks.is_multiple_of(2) {
            let mut in_code = false;
            for character in line.chars() {
                if character == '`' {
                    normalized.push_str(if in_code { r"\f[]" } else { r"\f[C]" });
                    in_code = !in_code;
                } else {
                    normalized.push(character);
                }
            }
        } else {
            normalized.push_str(line);
        }
    }

    normalized
}

fn normalize_roff_apostrophes(roff: &str) -> String {
    const APOSTROPHE: &str = r"\*(Aq";
    const SUFFIXES: [&str; 7] = ["s", "t", "d", "m", "re", "ve", "ll"];

    let mut normalized = String::with_capacity(roff.len());
    let mut remaining = roff;
    while let Some(position) = remaining.find(APOSTROPHE) {
        normalized.push_str(&remaining[..position]);
        let after = &remaining[position + APOSTROPHE.len()..];
        let follows_word = normalized
            .chars()
            .next_back()
            .is_some_and(char::is_alphanumeric);
        if follows_word && SUFFIXES.iter().any(|suffix| after.starts_with(suffix)) {
            normalized.push('\'');
        }
        remaining = after;
    }
    normalized.push_str(remaining);
    normalized
}

/// Keeps generated GFM stable across the roff emitted by clap_mangen and the
/// GFM writers in supported pandoc versions.
///
/// Newer combinations render the roff used for a value enumeration as a
/// blockquote and use Markdown hard-break spaces. The original checked-in CLI
/// reference used ordinary lists and backslash hard breaks. Normalize this
/// narrow construct instead of reformatting prose, so paragraph wrapping and
/// all user-facing text remain untouched.
fn normalize_pandoc_markdown(markdown: &str) -> String {
    let mut lines: Vec<String> = markdown.lines().map(str::to_string).collect();

    for possible_values in 0..lines.len() {
        if lines[possible_values].trim() != "*Possible values:*" {
            continue;
        }

        if possible_values >= 3
            && lines[possible_values - 1].trim().is_empty()
            && lines[possible_values - 2].is_empty()
            && lines[possible_values - 3].ends_with("  ")
        {
            let description = &mut lines[possible_values - 3];
            description.truncate(description.len() - 2);
            description.push('\\');
            lines[possible_values - 1] = "\\".to_string();
        } else if possible_values >= 2
            && lines[possible_values - 1].trim().is_empty()
            && lines[possible_values - 2].ends_with("  ")
        {
            lines[possible_values - 1] = "\\".to_string();
        }
    }

    normalize_possible_value_lists(&mut lines);

    let mut normalized = restore_escaped_markdown_links(&lines.join("\n"));
    if markdown.ends_with('\n') {
        normalized.push('\n');
    }
    normalized
}

fn restore_escaped_markdown_links(markdown: &str) -> String {
    let mut normalized = String::with_capacity(markdown.len());
    let mut remaining = markdown;

    while let Some(open) = remaining.find(r"\[") {
        normalized.push_str(&remaining[..open]);
        let candidate = &remaining[open + 2..];
        let Some(label_end) = candidate.find(r"\](") else {
            normalized.push_str(&remaining[open..]);
            return normalized;
        };
        if candidate[..label_end].contains('\n') {
            normalized.push_str(&remaining[open..open + 2]);
            remaining = candidate;
            continue;
        }
        let destination = &candidate[label_end + 3..];
        let Some(destination_end) = destination.find(')') else {
            normalized.push_str(&remaining[open..]);
            return normalized;
        };
        if destination[..destination_end]
            .chars()
            .any(|character| character == '\n' || character == ' ')
        {
            normalized.push_str(&remaining[open..open + 2]);
            remaining = candidate;
            continue;
        }

        normalized.push('[');
        normalized.push_str(&candidate[..label_end]);
        normalized.push_str("](");
        normalized.push_str(&destination[..=destination_end]);
        remaining = &destination[destination_end + 1..];
    }

    normalized.push_str(remaining);
    normalized
}

fn normalize_possible_value_lists(lines: &mut Vec<String>) {
    let mut heading = 0;
    while heading < lines.len() {
        if lines[heading].trim() != "*Possible values:*" {
            heading += 1;
            continue;
        }

        let start = heading + 1;
        let mut end = start;
        let mut items = Vec::new();
        let mut current = String::new();

        while end < lines.len() {
            let line = &lines[end];
            if let Some(item) = value_list_item(line) {
                if !current.is_empty() {
                    items.push(current);
                }
                current = item.to_string();
            } else if let Some(continuation) = value_list_continuation(line) {
                if !current.is_empty() {
                    current.push(' ');
                    current.push_str(continuation);
                }
            } else if !line.is_empty() && line != ">" {
                break;
            }
            end += 1;
        }
        if !current.is_empty() {
            items.push(current);
        }

        if items.is_empty() {
            heading += 1;
            continue;
        }

        let had_trailing_separator =
            end > start && (lines[end - 1].is_empty() || lines[end - 1] == ">");
        let item_count = items.len();
        let mut rendered = vec![String::new()];
        for (index, item) in items.into_iter().enumerate() {
            rendered.extend(wrap_value_list_item(&item));
            if index + 1 < item_count || had_trailing_separator {
                rendered.push(String::new());
            }
        }
        let rendered_len = rendered.len();
        lines.splice(start..end, rendered);
        heading = start + rendered_len;
    }
}

fn value_list_item(line: &str) -> Option<&str> {
    line.strip_prefix("> -")
        .or_else(|| line.strip_prefix("- "))
        .map(str::trim_start)
}

fn value_list_continuation(line: &str) -> Option<&str> {
    line.strip_prefix('>')
        .filter(|continuation| continuation.starts_with("   "))
        .or_else(|| line.starts_with("  ").then_some(line))
        .map(str::trim)
}

fn wrap_value_list_item(item: &str) -> Vec<String> {
    // pandoc 2's GFM writer wrapped these roff definition-list values at 72
    // columns. Keep that established layout when normalizing pandoc 3 output.
    const WIDTH: usize = 72;

    let mut wrapped = Vec::new();
    let mut line = String::from("- ");
    for word in item.split_whitespace() {
        let separator = usize::from(line.len() > 2);
        if line.len() + separator + word.len() > WIDTH && line.len() > 2 {
            wrapped.push(line);
            line = format!("  {word}");
        } else {
            if separator == 1 {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    wrapped.push(line);
    wrapped
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_pandoc_markdown, normalize_roff_for_pandoc, restore_escaped_markdown_links,
    };

    #[test]
    fn expands_clap_mangen_apostrophes_and_inline_code_for_pandoc() {
        let input = "Set a BMC\\*(Aqs password (use `credential rotate`)\n";
        let expected = "Set a BMC's password (use \\f[C]credential rotate\\f[])\n";

        assert_eq!(normalize_roff_for_pandoc(input), expected);
    }

    #[test]
    fn drops_roff_quote_marks_around_help_flags() {
        let input = "Print help (see a summary with \\*(Aq-h\\*(Aq)\n";
        let expected = "Print help (see a summary with -h)\n";

        assert_eq!(normalize_roff_for_pandoc(input), expected);
    }

    #[test]
    fn leaves_unpaired_roff_backticks_unchanged() {
        let input = "A lone ` is ordinary text.\n";

        assert_eq!(normalize_roff_for_pandoc(input), input);
    }

    #[test]
    fn restores_links_escaped_by_pandoc_without_touching_synopsis_brackets() {
        let input = r"Refer to \[Phone-home\](../../configuration.md#phone-home). \[**--flag**\]";
        let expected = r"Refer to [Phone-home](../../configuration.md#phone-home). \[**--flag**\]";

        assert_eq!(restore_escaped_markdown_links(input), expected);
    }

    #[test]
    fn normalizes_possible_value_lists_without_reflowing_prose() {
        let input = "Description that stays on its original line.  \n\n  \n*Possible values:*\n\n> - first\n>\n> -   second: description\n\nNext paragraph.\n";
        let expected = "Description that stays on its original line.\\\n\n\\\n*Possible values:*\n\n- first\n\n- second: description\n\nNext paragraph.\n";

        assert_eq!(normalize_pandoc_markdown(input), expected);
    }

    #[test]
    fn leaves_unrelated_markdown_unchanged() {
        let input = "A paragraph.\n\n> A real blockquote.\n";

        assert_eq!(normalize_pandoc_markdown(input), input);
    }

    #[test]
    fn normalizes_empty_descriptions_and_wrapped_value_details() {
        let input = "**--vendor**  \n  \n*Possible values:*\n\n> - first: a long description\n>   continued here\n";
        let expected = "**--vendor**  \n\\\n*Possible values:*\n\n- first: a long description continued here\n";

        assert_eq!(normalize_pandoc_markdown(input), expected);
    }

    #[test]
    fn wraps_value_details_independently_of_pandoc_list_indentation() {
        let pandoc_2 = "*Possible values:*\n\n-   flat: instances live directly on the underlay and use an operator-managed data plane instead of an overlay\n";
        let pandoc_3 = "*Possible values:*\n\n> - flat: instances live directly on the underlay and use an\n>   operator-managed data plane instead of an overlay\n";
        let expected = "*Possible values:*\n\n- flat: instances live directly on the underlay and use an\n  operator-managed data plane instead of an overlay\n";

        assert_eq!(normalize_pandoc_markdown(pandoc_2), expected);
        assert_eq!(normalize_pandoc_markdown(pandoc_3), expected);
    }
}

// A clap `StyledStr` rendered to plain text.
fn styled(s: Option<&clap::builder::StyledStr>) -> String {
    s.map(|s| s.to_string()).unwrap_or_default()
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").trim().to_string()
}

// The example command lines from a command's `after_long_help` EXAMPLES block:
// the lines beginning with the `$ ` shell prompt, with the prompt stripped.
fn example_commands(cmd: &Command) -> Option<String> {
    let help = cmd.get_after_long_help()?.to_string();
    let cmds: Vec<String> = help
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("$ "))
        .map(str::to_string)
        .collect();
    (!cmds.is_empty()).then(|| cmds.join("\n"))
}

fn slug(d: CliDomain) -> &'static str {
    match d {
        CliDomain::Hardware => "hardware",
        CliDomain::Network => "network",
        CliDomain::Tenant => "tenant",
        CliDomain::Admin => "admin",
    }
}

fn intro(d: CliDomain) -> &'static str {
    match d {
        CliDomain::Hardware => {
            "Live hardware and lifecycle operations: machines, BMC, DPUs, firmware \
             and component lifecycle, attestation, low-level passthrough (Redfish, \
             RMS, MLX), and operator utilities."
        }
        CliDomain::Network => {
            "VPCs, peerings, prefixes, network segments and devices, security groups, \
             IB/NVLink fabric partitions, IP/domain lookups, and resource pools."
        }
        CliDomain::Tenant => {
            "Tenants and tenant keysets, instances and instance types, compute \
             allocations, the declarative `expected-*` inventory, operating systems \
             and OS images, iPXE templates, extension services, and the site explorer."
        }
        CliDomain::Admin => "CLI and system utilities.",
    }
}
