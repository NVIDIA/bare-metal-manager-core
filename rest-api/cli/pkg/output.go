// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	cli "github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

// allowedOutputFormats is the canonical, ordered set of values the --output
// flag accepts. Kept as a slice (not a map) so error messages can render the
// list deterministically.
var allowedOutputFormats = []string{"json", "yaml", "table"}

// ValidateOutputFormat returns an error if format is outside the allowed set.
// The empty string is treated as valid so the StringFlag default ("json") and
// callers that pass an unset value continue to work.
//
// Without this validator, FormatOutput silently routed any unknown value to
// formatJSON, so a typo like `--output xml` exited 0 and produced JSON --
// dangerous in scripts that branch on the requested format.
func ValidateOutputFormat(format string) error {
	if format == "" {
		return nil
	}
	for _, allowed := range allowedOutputFormats {
		if format == allowed {
			return nil
		}
	}
	return fmt.Errorf(
		"invalid value %q for flag --output: allowed values are %s",
		format,
		strings.Join(allowedOutputFormats, ", "),
	)
}

// validateOutputFlag is the urfave/cli StringFlag.Action callback. It runs
// after the flag value is parsed and returns the same error as
// ValidateOutputFormat so an invalid --output value fails before any auth or
// HTTP work in the command Action.
func validateOutputFlag(_ *cli.Context, value string) error {
	return ValidateOutputFormat(value)
}

func FormatOutput(data []byte, format string) error {
	switch format {
	case "", "json":
		return formatJSON(data)
	case "yaml":
		return formatYAML(data)
	case "table":
		return formatTable(data)
	default:
		// Defense in depth -- the StringFlag Action validator should catch
		// invalid values at flag-parse time, but if FormatOutput is ever
		// called from a non-CLI code path with an unvalidated value, fail
		// loudly instead of silently picking a format the caller didn't ask
		// for.
		return ValidateOutputFormat(format)
	}
}

func formatJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		_, err = os.Stdout.Write(data)
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func formatYAML(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		_, err = os.Stdout.Write(data)
		return err
	}
	return yaml.NewEncoder(os.Stdout).Encode(v)
}

var tableFields = []string{"id", "name", "status", "created", "updated"}

func formatTable(data []byte) error {
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		_, err = os.Stdout.Write(data)
		return err
	}

	var items []map[string]interface{}
	switch v := raw.(type) {
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				items = append(items, m)
			}
		}
	case map[string]interface{}:
		items = append(items, v)
	default:
		return formatJSON(data)
	}

	if len(items) == 0 {
		fmt.Println("(no results)")
		return nil
	}

	var cols []string
	for _, f := range tableFields {
		if _, ok := items[0][f]; ok {
			cols = append(cols, f)
		}
	}
	if len(cols) == 0 {
		return formatJSON(data)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for i, c := range cols {
		if i > 0 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprint(w, c)
	}
	fmt.Fprintln(w)

	for _, item := range items {
		for i, c := range cols {
			if i > 0 {
				fmt.Fprint(w, "\t")
			}
			fmt.Fprintf(w, "%v", item[c])
		}
		fmt.Fprintln(w)
	}

	return w.Flush()
}
