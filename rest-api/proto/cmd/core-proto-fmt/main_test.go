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
import "codegen/v1/extern_path.proto";

option (carbide.codegen.v1.imported_extern_path) = {
  protobuf_type: ".google.protobuf.Timestamp"
  rust_type: "crate::Timestamp"
};

message Example {
  option (carbide.codegen.v1.message_derive) = "serde::Serialize";
  option (carbide.codegen.v1.message_derive) = "serde::Deserialize";
  option (carbide.codegen.v1.message_extern_path) = "::example::External";

  enum State {
    option (carbide.codegen.v1.enum_derive) = "serde::Serialize";
    option (carbide.codegen.v1.enum_extern_path) = "::example::State";
    STATE_UNSPECIFIED = 0;
  }

  string value = 1;
}
`

	output := removeCodegenAnnotations(input)
	for _, removed := range []string{
		"codegen/v1/derive.proto",
		"codegen/v1/extern_path.proto",
		"carbide.codegen.v1.message_derive",
		"carbide.codegen.v1.enum_derive",
		"carbide.codegen.v1.message_extern_path",
		"carbide.codegen.v1.enum_extern_path",
		"carbide.codegen.v1.imported_extern_path",
		"crate::Timestamp",
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

func TestRemoveCodegenAnnotationsPreservesUnrelatedWhitespace(t *testing.T) {
	input := `message First {
  option (carbide.codegen.v1.message_extern_path) = "::example::First";
}


message Second {}
`
	want := `message First {
}


message Second {}
`

	if got := removeCodegenAnnotations(input); got != want {
		t.Errorf("removeCodegenAnnotations() changed unrelated whitespace:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}
