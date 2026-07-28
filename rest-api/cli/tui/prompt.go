// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// PromptText displays a label and reads a line of text input.
func PromptText(label string, required bool) (string, error) {
	for {
		fmt.Printf("%s: ", Bold(label))
		input, err := readPromptLine()
		if err != nil {
			return "", err
		}
		text := strings.TrimSpace(input)
		if text == "" && required {
			fmt.Println(Red("  (required)"))
			continue
		}
		return text, nil
	}
}

// PromptSecret reads one line without echo when stdin is a terminal. Piped
// input keeps the normal line-input path so commands remain scriptable and tests
// can supply deterministic input.
func PromptSecret(label string, required bool) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return PromptText(label, required)
	}

	for {
		fmt.Printf("%s: ", Bold(label))
		input, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("reading secret input: %w", err)
		}
		text := strings.TrimSpace(string(input))
		if text == "" && required {
			fmt.Println(Red("  (required)"))
			continue
		}
		return text, nil
	}
}

// PromptConfirm displays a y/N confirmation prompt.
func PromptConfirm(label string) (bool, error) {
	fmt.Printf("%s [y/N] ", Bold(label))
	input, err := readPromptLine()
	if err != nil {
		return false, err
	}
	answer := strings.TrimSpace(strings.ToLower(input))
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
	display := strings.Join(options, "/")
	suffix := fmt.Sprintf("[%s]", display)
	if defaultValue != "" {
		suffix = fmt.Sprintf("[%s, default %s]", display, defaultValue)
	}
	for {
		fmt.Printf("%s %s: ", Bold(label), suffix)
		input, err := readPromptLine()
		if err != nil {
			return "", err
		}
		text := strings.TrimSpace(input)
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

// readPromptLine reads exactly one logical line without buffering past its
// newline. Generated forms ask several questions in sequence; using a fresh
// bufio.Scanner per question can consume later piped lines into the first
// scanner's private buffer. Byte-wise reads preserve terminal behavior while
// keeping scripted input and tests deterministic.
func readPromptLine() (string, error) {
	var result strings.Builder
	var one [1]byte
	for {
		n, err := os.Stdin.Read(one[:])
		if n > 0 {
			switch one[0] {
			case '\n':
				return result.String(), nil
			case '\r':
				continue
			default:
				result.WriteByte(one[0])
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if result.Len() > 0 {
					return result.String(), nil
				}
				return "", fmt.Errorf("input cancelled")
			}
			return "", fmt.Errorf("reading input: %w", err)
		}
	}
}
