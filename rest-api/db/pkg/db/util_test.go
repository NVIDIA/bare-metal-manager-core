// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGetStrPtr(t *testing.T) {
	type args struct {
		s string
	}

	input := "test"

	tests := []struct {
		name string
		args args
		want *string
	}{
		{
			name: "get pointer for string",
			args: args{
				s: input,
			},
			want: &input,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetStrPtr(tt.args.s)

			if *got != *tt.want {
				t.Errorf("GetStrPtr() = %v, want %v", *got, *tt.want)
			}
		})
	}
}

func TestGetTimePtr(t *testing.T) {
	type args struct {
		t time.Time
	}

	input := GetCurTime()

	tests := []struct {
		name string
		args args
		want *time.Time
	}{
		{
			name: "get pointer for time",
			args: args{
				t: input,
			},
			want: &input,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetTimePtr(tt.args.t)

			if *got != *tt.want {
				t.Errorf("GetTimePtr() = %v, want %v", *got, *tt.want)
			}
		})
	}
}

func TestGetUUIDPtr(t *testing.T) {
	type args struct {
		u uuid.UUID
	}

	input := uuid.New()

	tests := []struct {
		name string
		args args
		want *uuid.UUID
	}{
		{
			name: "get pointer for UUID",
			args: args{
				u: input,
			},
			want: &input,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetUUIDPtr(tt.args.u); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetUUIDPtr() = %v, want %v", *got, *tt.want)
			}
		})
	}
}

func TestGetBoolPtr(t *testing.T) {
	type args struct {
		b bool
	}

	input := true

	tests := []struct {
		name string
		args args
		want *bool
	}{
		{
			name: "get pointer for bool",
			args: args{
				b: input,
			},
			want: &input,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetBoolPtr(tt.args.b); *got != *tt.want {
				t.Errorf("GetBoolPtr() = %v, want %v", *got, *tt.want)
			}
		})
	}
}

func TestGetIntPtr(t *testing.T) {
	type args struct {
		i int
	}

	input := 10

	tests := []struct {
		name string
		args args
		want *int
	}{
		{
			name: "get pointer for int",
			args: args{
				i: input,
			},
			want: &input,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetIntPtr(tt.args.i); *got != *tt.want {
				t.Errorf("GetIntPtr() = %v, want %v", *got, *tt.want)
			}
		})
	}
}

func TestIsStrInSlice(t *testing.T) {
	type args struct {
		s  string
		sl []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "is string in slice",
			args: args{
				s:  "test",
				sl: []string{"test", "test2"},
			},
			want: true,
		},

		{
			name: "is string not in slice",
			args: args{
				s:  "test3",
				sl: []string{"test", "test2"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsStrInSlice(tt.args.s, tt.args.sl); got != tt.want {
				t.Errorf("IsStrInSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetStringToUint64Hash(t *testing.T) {
	id := uuid.New().String()
	h1 := GetStringToUint64Hash(id)
	h2 := GetStringToUint64Hash(id)
	assert.Equal(t, h1, h2)
}

func TestGetStringToTsQuery(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "single word",
			input: "hello",
			want:  "hello",
		},
		{
			name:  "single space between words",
			input: "hello world",
			want:  "hello | world",
		},
		{
			name:  "double space between words",
			input: "hello  world",
			want:  "hello | world",
		},
		{
			name:  "multiple spaces between words",
			input: "hello    world   foo",
			want:  "hello | world | foo",
		},
		{
			name:  "whitespace only",
			input: "   ",
			want:  "",
		},
		{
			name:  "mixed whitespace only",
			input: "\t \n",
			want:  "",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "already has OR operator",
			input: "hello | world",
			want:  "hello | world",
		},
		{
			name:  "already has AND operator",
			input: "hello & world",
			want:  "hello & world",
		},
		{
			name:  "already has OR operator with surrounding whitespace",
			input: " foo | bar ",
			want:  "foo | bar",
		},
		{
			name:  "standalone OR operator",
			input: "|",
			want:  "",
		},
		{
			name:  "standalone AND operator",
			input: "&",
			want:  "",
		},
		{
			name:  "standalone NOT operator",
			input: "!",
			want:  "",
		},
		{
			name:  "leading OR operator",
			input: "| foo",
			want:  "",
		},
		{
			name:  "leading AND operator",
			input: "& foo",
			want:  "",
		},
		{
			name:  "leading NOT operator",
			input: "! foo",
			want:  "",
		},
		{
			name:  "trailing OR operator",
			input: "foo |",
			want:  "",
		},
		{
			name:  "trailing AND operator",
			input: "foo &",
			want:  "",
		},
		{
			name:  "consecutive OR operators",
			input: "foo | |",
			want:  "",
		},
		{
			name:  "consecutive AND operators",
			input: "foo & &",
			want:  "",
		},
		{
			name:  "mixed consecutive operators",
			input: "foo | & bar",
			want:  "",
		},
		{
			name:  "unsupported NOT operator",
			input: "foo ! bar",
			want:  "",
		},
		{
			name:  "embedded OR operator",
			input: "foo|bar",
			want:  "",
		},
		{
			name:  "embedded AND operator",
			input: "foo&bar",
			want:  "",
		},
		{
			name:  "double OR operator token",
			input: "foo || bar",
			want:  "",
		},
		{
			name:  "double AND operator token",
			input: "foo && bar",
			want:  "",
		},
		{
			name:  "missing explicit operator between terms",
			input: "foo | bar baz",
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetStringToTsQuery(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeSearchQuery(t *testing.T) {
	tests := []struct {
		name        string
		input       *string
		wantQuery   string
		wantTsQuery *string
		wantOK      bool
	}{
		{
			name:   "nil",
			input:  nil,
			wantOK: false,
		},
		{
			name:   "blank",
			input:  GetStrPtr("   "),
			wantOK: false,
		},
		{
			name:        "valid multi word",
			input:       GetStrPtr(" foo bar "),
			wantQuery:   "foo bar",
			wantTsQuery: GetStrPtr("foo | bar"),
			wantOK:      true,
		},
		{
			name:        "valid explicit OR operator",
			input:       GetStrPtr("foo | bar"),
			wantQuery:   "foo | bar",
			wantTsQuery: GetStrPtr("foo | bar"),
			wantOK:      true,
		},
		{
			name:   "standalone operator",
			input:  GetStrPtr("|"),
			wantOK: false,
		},
		{
			name:   "leading operator",
			input:  GetStrPtr("| foo"),
			wantOK: false,
		},
		{
			name:   "trailing operator",
			input:  GetStrPtr("foo |"),
			wantOK: false,
		},
		{
			name:   "consecutive operators",
			input:  GetStrPtr("foo | |"),
			wantOK: false,
		},
		{
			name:   "unsupported NOT operator",
			input:  GetStrPtr("foo ! bar"),
			wantOK: false,
		},
		{
			name:   "embedded operator",
			input:  GetStrPtr("foo|bar"),
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotQuery, gotTsQuery, gotOK := NormalizeSearchQuery(tt.input)
			assert.Equal(t, tt.wantQuery, gotQuery)
			assert.Equal(t, tt.wantTsQuery, gotTsQuery)
			assert.Equal(t, tt.wantOK, gotOK)
		})
	}
}

func TestTrimSearchQuery(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{
			name:  "absent equivalent",
			input: "",
			want:  "",
			ok:    false,
		},
		{
			name:  "whitespace only",
			input: "   ",
			want:  "",
			ok:    false,
		},
		{
			name:  "mixed whitespace only",
			input: "\t \n",
			want:  "",
			ok:    false,
		},
		{
			name:  "trimmed",
			input: " query ",
			want:  "query",
			ok:    true,
		},
		{
			name:  "internal whitespace",
			input: "foo  bar",
			want:  "foo  bar",
			ok:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := TrimSearchQuery(tt.input)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.ok, ok)
		})
	}
}

func TestCompareStringSlicesIgnoreOrder(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{
			name: "empty slices",
			a:    []string{},
			b:    []string{},
			want: true,
		},
		{
			name: "nil slices",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "one nil one empty",
			a:    nil,
			b:    []string{},
			want: true,
		},
		{
			name: "identical slices same order",
			a:    []string{"a", "b", "c"},
			b:    []string{"a", "b", "c"},
			want: true,
		},
		{
			name: "identical slices different order",
			a:    []string{"a", "b", "c"},
			b:    []string{"c", "a", "b"},
			want: true,
		},
		{
			name: "different length slices",
			a:    []string{"a", "b"},
			b:    []string{"a", "b", "c"},
			want: false,
		},
		{
			name: "same length different content",
			a:    []string{"a", "b", "c"},
			b:    []string{"a", "b", "d"},
			want: false,
		},
		{
			name: "single element equal",
			a:    []string{"test"},
			b:    []string{"test"},
			want: true,
		},
		{
			name: "single element different",
			a:    []string{"test1"},
			b:    []string{"test2"},
			want: false,
		},
		{
			name: "duplicates same order",
			a:    []string{"a", "b", "a"},
			b:    []string{"a", "b", "a"},
			want: true,
		},
		{
			name: "duplicates different order",
			a:    []string{"a", "b", "a"},
			b:    []string{"a", "a", "b"},
			want: true,
		},
		{
			name: "duplicates different count",
			a:    []string{"a", "b", "a"},
			b:    []string{"a", "b", "b"},
			want: false,
		},
		{
			name: "complex case with multiple duplicates",
			a:    []string{"role1", "role2", "role3", "role1", "role2"},
			b:    []string{"role2", "role1", "role2", "role3", "role1"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareStringSlicesIgnoreOrder(tt.a, tt.b)
			assert.Equal(t, tt.want, got, "CompareStringSlicesIgnoreOrder(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		})
	}
}
