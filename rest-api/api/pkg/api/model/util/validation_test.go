// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"fmt"
	"testing"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateLabels(t *testing.T) {
	assert.NoError(t, ValidateLabels(nil))
	assert.NoError(t, ValidateLabels(map[string]string{}))

	tooMany := make(map[string]string)
	for i := range LabelCountMax + 1 {
		tooMany[fmt.Sprintf("k%d", i)] = "v"
	}
	err := ValidateLabels(tooMany)
	require.Error(t, err)
	var verrs validation.Errors
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, ErrValidationLabelCount, verrs["labels"])

	err = ValidateLabels(map[string]string{"": "v"})
	require.Error(t, err)
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, ErrValidationLabelKeyEmpty, verrs["labels"])

	err = ValidateLabels(map[string]string{"   ": "v"})
	require.Error(t, err)
	require.ErrorAs(t, err, &verrs)
	// Whitespace-only key fails Match before Length (see ValidateLabels).
	assert.Equal(t, "label key consists only of whitespace", verrs["labels"].Error())

	err = ValidateLabels(map[string]string{"k": string(make([]byte, LabelValueMaxLength+1))})
	require.Error(t, err)
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, ErrValidationLabelValueLength.Error(), verrs["labels"].Error())

	assert.NoError(t, ValidateLabels(map[string]string{"ok": "ok"}))
}

func TestValidateNameCharacters(t *testing.T) {
	val := 0
	// test error when string not passed
	assert.NotNil(t, ValidateNameCharacters(val))
	assert.NotNil(t, ValidateNameCharacters(&val))
	assert.NotNil(t, ValidateNameCharacters(nil))
	tests := []struct {
		desc      string
		names     []string
		expectErr bool
	}{
		{
			desc:      "error with leading whitespaces",
			names:     []string{" hello", "\thello", "\nhello", "     "},
			expectErr: true,
		},
		{
			desc:      "errors with trailing whitespaces",
			names:     []string{"hello ", "hello\t", "hello\n"},
			expectErr: true,
		},
		{
			desc:      "success cases",
			names:     []string{"hel lo", "hel \t lo", "hel&&lo"},
			expectErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			for _, s := range tc.names {
				err := ValidateNameCharacters(s)
				assert.Equal(t, tc.expectErr, err != nil)
				err = ValidateNameCharacters(&s)
				assert.Equal(t, tc.expectErr, err != nil)
			}
		})
	}
}
