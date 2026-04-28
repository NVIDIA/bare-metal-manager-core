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

/// Transform a raw `pg_dump --schema-only` output into idempotent
/// SQL that can be applied cleanly over both fresh and existing databases.
pub fn transform_schema(raw: &str) -> String {
    let lines: Vec<&str> = raw.lines().collect();
    let mut output = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Strip psql meta-commands (\restrict, \unrestrict, etc).
        if line.starts_with('\\') {
            i += 1;
            continue;
        }

        // Skip pg_dump preamble SET commands and search_path manipulation.
        if line.starts_with("SET ") || line.starts_with("SELECT pg_catalog.") {
            i += 1;
            continue;
        }

        // Skip COMMENT ON EXTENSION lines.
        if line.starts_with("COMMENT ON EXTENSION") {
            i += 1;
            continue;
        }

        // CREATE TABLE -> CREATE TABLE IF NOT EXISTS.
        if line.starts_with("CREATE TABLE ") && !line.contains("IF NOT EXISTS") {
            output.push(line.replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1));
            i += 1;
            continue;
        }

        // CREATE SEQUENCE -> CREATE SEQUENCE IF NOT EXISTS.
        if line.starts_with("CREATE SEQUENCE ") && !line.contains("IF NOT EXISTS") {
            output.push(line.replacen("CREATE SEQUENCE ", "CREATE SEQUENCE IF NOT EXISTS ", 1));
            i += 1;
            continue;
        }

        // CREATE INDEX / CREATE UNIQUE INDEX -> IF NOT EXISTS.
        if (line.starts_with("CREATE INDEX ") || line.starts_with("CREATE UNIQUE INDEX "))
            && !line.contains("IF NOT EXISTS")
        {
            if line.starts_with("CREATE UNIQUE INDEX ") {
                output.push(line.replacen(
                    "CREATE UNIQUE INDEX ",
                    "CREATE UNIQUE INDEX IF NOT EXISTS ",
                    1,
                ));
            } else {
                output.push(line.replacen("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1));
            }
            i += 1;
            continue;
        }

        // CREATE EXTENSION -> IF NOT EXISTS.
        if line.starts_with("CREATE EXTENSION ") && !line.contains("IF NOT EXISTS") {
            output.push(line.replacen("CREATE EXTENSION ", "CREATE EXTENSION IF NOT EXISTS ", 1));
            i += 1;
            continue;
        }

        // CREATE FUNCTION / CREATE PROCEDURE -> CREATE OR REPLACE.
        if line.starts_with("CREATE FUNCTION ") {
            output.push(line.replacen("CREATE FUNCTION ", "CREATE OR REPLACE FUNCTION ", 1));
            i += 1;
            continue;
        }
        if line.starts_with("CREATE PROCEDURE ") {
            output.push(line.replacen("CREATE PROCEDURE ", "CREATE OR REPLACE PROCEDURE ", 1));
            i += 1;
            continue;
        }

        // CREATE VIEW -> CREATE OR REPLACE VIEW.
        if line.starts_with("CREATE VIEW ") {
            output.push(line.replacen("CREATE VIEW ", "CREATE OR REPLACE VIEW ", 1));
            i += 1;
            continue;
        }

        // CREATE MATERIALIZED VIEW -> IF NOT EXISTS.
        if line.starts_with("CREATE MATERIALIZED VIEW ") && !line.contains("IF NOT EXISTS") {
            output.push(line.replacen(
                "CREATE MATERIALIZED VIEW ",
                "CREATE MATERIALIZED VIEW IF NOT EXISTS ",
                1,
            ));
            i += 1;
            continue;
        }

        // CREATE TRIGGER -> CREATE OR REPLACE TRIGGER.
        if line.starts_with("CREATE TRIGGER ") {
            output.push(line.replacen("CREATE TRIGGER ", "CREATE OR REPLACE TRIGGER ", 1));
            i += 1;
            continue;
        }

        // CREATE TYPE -> wrap in DO $$ EXCEPTION block.
        if line.starts_with("CREATE TYPE ") {
            let (stmt, new_i) = collect_statement(&lines, i);
            output.push(wrap_in_exception_block(&stmt));
            i = new_i + 1;
            continue;
        }

        // ALTER TABLE ONLY ... followed by ADD CONSTRAINT on next line.
        // We do this because pg_dump splits these across two lines:
        //   ALTER TABLE ONLY public.foo
        //       ADD CONSTRAINT bar_pkey PRIMARY KEY (id);
        if line.starts_with("ALTER TABLE ONLY ")
            && !line.trim_end().ends_with(';')
            && lines
                .get(i + 1)
                .is_some_and(|next| next.trim_start().starts_with("ADD CONSTRAINT "))
        {
            let (stmt, new_i) = collect_statement(&lines, i);
            output.push(wrap_in_exception_block(&stmt));
            i = new_i + 1;
            continue;
        }

        // ALTER TABLE ... ADD GENERATED ALWAYS AS IDENTITY (multi-line).
        if line.starts_with("ALTER TABLE ") && line.contains("ADD GENERATED ALWAYS AS IDENTITY") {
            let (stmt, new_i) = collect_statement(&lines, i);
            output.push(wrap_in_exception_block(&stmt));
            i = new_i + 1;
            continue;
        }

        // All other ALTER TABLE statements (SET DEFAULT, SET NOT NULL, etc.) are
        // idempotent by nature -- pass through as-is.
        // Everything else also passes through.
        output.push(line.to_string());
        i += 1;
    }

    collapse_blank_lines(&output.join("\n"))
}

/// Collect a multi-line SQL statement from `start` until a line ends with `;`.
fn collect_statement(lines: &[&str], start: usize) -> (String, usize) {
    let mut parts = vec![lines[start].to_string()];
    let mut j = start;
    while j < lines.len() - 1 && !lines[j].trim_end().ends_with(';') {
        j += 1;
        parts.push(lines[j].to_string());
    }
    (parts.join("\n"), j)
}

/// Wrap a SQL statement in a `DO $$ BEGIN EXECUTE '...'; EXCEPTION ... END $$;`
/// block so that it silently succeeds if the object already exists.
fn wrap_in_exception_block(stmt: &str) -> String {
    let escaped = stmt.replace('\'', "''");
    format!(
        "DO $$ BEGIN\n\
         \x20   EXECUTE '{escaped}';\n\
         EXCEPTION WHEN duplicate_object OR duplicate_table OR invalid_table_definition THEN null;\n\
         END $$;"
    )
}

/// Collapse runs of 3+ blank lines down to at most 2.
fn collapse_blank_lines(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut blank_count = 0;

    for line in s.lines() {
        if line.is_empty() {
            blank_count += 1;
            if blank_count <= 2 {
                result.push('\n');
            }
        } else {
            blank_count = 0;
            result.push_str(line);
            result.push('\n');
        }
    }

    result
}

/// Clean a `pg_dump --data-only` output by stripping SET lines, psql
/// meta-commands, and other preamble, keeping only the INSERT statements.
pub fn clean_data_dump(raw: &str) -> String {
    raw.lines()
        .filter(|line| {
            !line.starts_with("SET ")
                && !line.starts_with("SELECT pg_catalog.")
                && !line.starts_with('\\')
                && !line.starts_with("COMMENT ON EXTENSION")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_table_if_not_exists() {
        let input = "CREATE TABLE public.machines (\n    id uuid NOT NULL\n);";
        let output = transform_schema(input);
        assert!(output.contains("CREATE TABLE IF NOT EXISTS public.machines"));
        assert!(!output.contains("\nCREATE TABLE public"));
    }

    #[test]
    fn test_create_index_if_not_exists() {
        let input = "CREATE INDEX idx_foo ON public.machines USING btree (id);";
        let output = transform_schema(input);
        assert!(output.contains("CREATE INDEX IF NOT EXISTS idx_foo"));
    }

    #[test]
    fn test_create_unique_index_if_not_exists() {
        let input = "CREATE UNIQUE INDEX machines_pkey ON public.machines USING btree (id);";
        let output = transform_schema(input);
        assert!(output.contains("CREATE UNIQUE INDEX IF NOT EXISTS machines_pkey"));
    }

    #[test]
    fn test_create_extension_if_not_exists() {
        let input = "CREATE EXTENSION pgcrypto WITH SCHEMA public;";
        let output = transform_schema(input);
        assert!(output.contains("CREATE EXTENSION IF NOT EXISTS pgcrypto"));
    }

    #[test]
    fn test_create_or_replace_function() {
        let input = "CREATE FUNCTION public.my_func() RETURNS void\n    LANGUAGE sql\n    AS $$ SELECT 1; $$;";
        let output = transform_schema(input);
        assert!(output.contains("CREATE OR REPLACE FUNCTION public.my_func()"));
    }

    #[test]
    fn test_create_or_replace_view() {
        let input = "CREATE VIEW public.my_view AS\n SELECT 1 AS id;";
        let output = transform_schema(input);
        assert!(output.contains("CREATE OR REPLACE VIEW public.my_view"));
    }

    #[test]
    fn test_create_or_replace_trigger() {
        let input = "CREATE TRIGGER my_trigger BEFORE UPDATE ON public.machines FOR EACH ROW EXECUTE FUNCTION my_func();";
        let output = transform_schema(input);
        assert!(output.contains("CREATE OR REPLACE TRIGGER my_trigger"));
    }

    #[test]
    fn test_create_sequence_if_not_exists() {
        let input =
            "CREATE SEQUENCE public.my_seq\n    START WITH 1\n    INCREMENT BY 1\n    CACHE 1;";
        let output = transform_schema(input);
        assert!(output.contains("CREATE SEQUENCE IF NOT EXISTS public.my_seq"));
    }

    #[test]
    fn test_enum_type_wrapped_in_exception_block() {
        let input = "CREATE TYPE public.machine_state AS ENUM (\n    'init',\n    'ready'\n);";
        let output = transform_schema(input);
        assert!(output.contains("DO $$ BEGIN"));
        assert!(output.contains("EXECUTE '"));
        assert!(output.contains("CREATE TYPE public.machine_state AS ENUM"));
        assert!(output.contains("EXCEPTION WHEN duplicate_object"));
    }

    #[test]
    fn test_enum_single_quotes_escaped() {
        let input = "CREATE TYPE public.my_type AS ENUM (\n    'it''s',\n    'ok'\n);";
        let output = transform_schema(input);
        // The original single quotes in ENUM values get
        // double-escaped inside the EXECUTE string.
        assert!(output.contains("it''''s"));
    }

    #[test]
    fn test_alter_table_add_constraint_wrapped() {
        let input =
            "ALTER TABLE ONLY public.machines\n    ADD CONSTRAINT machines_pkey PRIMARY KEY (id);";
        let output = transform_schema(input);
        assert!(output.contains("DO $$ BEGIN"));
        assert!(output.contains("ADD CONSTRAINT machines_pkey PRIMARY KEY"));
        assert!(output.contains("EXCEPTION WHEN duplicate_object"));
    }

    #[test]
    fn test_alter_table_set_default_passes_through() {
        let input = "ALTER TABLE ONLY public.machines ALTER COLUMN state SET DEFAULT 'init'::text;";
        let output = transform_schema(input);
        assert!(output.contains("ALTER TABLE ONLY public.machines ALTER COLUMN state SET DEFAULT"));
        assert!(!output.contains("DO $$ BEGIN"));
    }

    #[test]
    fn test_add_generated_identity_wrapped() {
        let input = "ALTER TABLE public.history ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (\n    SEQUENCE NAME public.history_id_seq\n    START WITH 1\n    CACHE 1\n);";
        let output = transform_schema(input);
        assert!(output.contains("DO $$ BEGIN"));
        assert!(output.contains("ADD GENERATED ALWAYS AS IDENTITY"));
        assert!(output.contains("EXCEPTION WHEN"));
    }

    #[test]
    fn test_strips_psql_metacommands() {
        let input =
            "\\restrict abc123\nCREATE TABLE public.foo (\n    id int\n);\n\\unrestrict abc123";
        let output = transform_schema(input);
        assert!(!output.contains("\\restrict"));
        assert!(!output.contains("\\unrestrict"));
        assert!(output.contains("CREATE TABLE IF NOT EXISTS"));
    }

    #[test]
    fn test_strips_set_commands() {
        let input = "SET statement_timeout = 0;\nSET lock_timeout = 0;\nCREATE TABLE public.foo (\n    id int\n);";
        let output = transform_schema(input);
        assert!(!output.contains("SET statement_timeout"));
        assert!(output.contains("CREATE TABLE IF NOT EXISTS"));
    }

    #[test]
    fn test_clean_data_dump() {
        let input = "SET statement_timeout = 0;\n\
                      \\restrict abc\n\
                      INSERT INTO public.foo VALUES (1, 'bar') ON CONFLICT DO NOTHING;\n\
                      \\unrestrict abc";
        let output = clean_data_dump(input);
        assert!(!output.contains("SET "));
        assert!(!output.contains("\\restrict"));
        assert!(output.contains("INSERT INTO public.foo"));
    }

    #[test]
    fn test_preserves_already_idempotent() {
        let input = "CREATE TABLE IF NOT EXISTS public.foo (\n    id int\n);";
        let output = transform_schema(input);
        // Should not double up "IF NOT EXISTS".
        assert!(!output.contains("IF NOT EXISTS IF NOT EXISTS"));
        assert!(output.contains("CREATE TABLE IF NOT EXISTS public.foo"));
    }
}
