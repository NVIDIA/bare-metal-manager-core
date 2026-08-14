// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestRemoveCodegenAnnotations(t *testing.T) {
	input := `syntax = "proto3";

import "codegen/v1/derive.proto";

message Example {
  option (carbide.codegen.v1.message_derive) = "serde::Serialize";
  option (carbide.codegen.v1.message_derive) = "serde::Deserialize";

  enum State {
    option (carbide.codegen.v1.enum_derive) = "serde::Serialize";
    STATE_UNSPECIFIED = 0;
  }

  string value = 1;
}
`

	output := removeCodegenAnnotations(input)
	for _, removed := range []string{
		"codegen/v1/derive.proto",
		"carbide.codegen.v1.message_derive",
		"carbide.codegen.v1.enum_derive",
	} {
		if strings.Contains(output, removed) {
			t.Errorf("output still contains Rust codegen annotation %q", removed)
		}
	}
	if !strings.Contains(output, "string value = 1;") {
		t.Error("output lost protobuf schema content")
	}
	if strings.Contains(output, "\n\n\n") {
		t.Error("output contains extra blank lines after removing codegen annotations")
	}
}
