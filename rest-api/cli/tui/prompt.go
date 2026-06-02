// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// PromptText displays a label and reads a line of text input.
func PromptText(label string, required bool) (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%s: ", Bold(label))
		if !scanner.Scan() {
			return "", fmt.Errorf("input cancelled")
		}
		text := strings.TrimSpace(scanner.Text())
		if text == "" && required {
			fmt.Println(Red("  (required)"))
			continue
		}
		return text, nil
	}
}

// PromptConfirm displays a y/N confirmation prompt.
func PromptConfirm(label string) (bool, error) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("%s [y/N] ", Bold(label))
	if !scanner.Scan() {
		return false, fmt.Errorf("input cancelled")
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	return answer == "y" || answer == "yes", nil
}

// PromptChoice displays a label with a list of options and reads a selection.
// If the user enters an empty string and a default is provided, the default is
// returned. Input matching is case-insensitive and the canonical option value
// is returned. A non-empty defaultValue must appear in options (case
// insensitively) or PromptChoice returns an error before prompting -- a
// misconfigured default must not be able to bypass choice validation.
func PromptChoice(label string, options []string, defaultValue string) (string, error) {
	if len(options) == 0 {
		return "", fmt.Errorf("no options provided")
	}
	if defaultValue != "" {
		canonical := ""
		for _, opt := range options {
			if strings.EqualFold(defaultValue, opt) {
				canonical = opt
				break
			}
		}
		if canonical == "" {
			return "", fmt.Errorf("default value %q is not in allowed options %v", defaultValue, options)
		}
		defaultValue = canonical
	}
	scanner := bufio.NewScanner(os.Stdin)
	display := strings.Join(options, "/")
	suffix := fmt.Sprintf("[%s]", display)
	if defaultValue != "" {
		suffix = fmt.Sprintf("[%s, default %s]", display, defaultValue)
	}
	for {
		fmt.Printf("%s %s: ", Bold(label), suffix)
		if !scanner.Scan() {
			return "", fmt.Errorf("input cancelled")
		}
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			if defaultValue != "" {
				return defaultValue, nil
			}
			fmt.Println(Red("  (required)"))
			continue
		}
		for _, opt := range options {
			if strings.EqualFold(text, opt) {
				return opt, nil
			}
		}
		fmt.Println(Red(fmt.Sprintf("  (must be one of %s)", display)))
	}
}
