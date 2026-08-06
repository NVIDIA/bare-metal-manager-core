// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package grpcproxy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactAndMergeSecretsRoundTrip(t *testing.T) {
	orig := []byte(`{"credentialType":"SiteWideBmcRoot","password":"s3cr3t","macAddress":"aa:bb"}`)

	redacted, secretsJSON, err := RedactSecrets(orig, []string{"password"})
	require.NoError(t, err)

	// The redacted payload must not contain the secret value, but must keep the
	// non-secret fields readable and mark the field as redacted.
	assert.NotContains(t, string(redacted), "s3cr3t")
	assert.Contains(t, string(redacted), RedactedPlaceholder)
	assert.Contains(t, string(redacted), "macAddress")
	require.NotEmpty(t, secretsJSON)
	assert.Contains(t, string(secretsJSON), "s3cr3t")

	// Merging the secrets back reproduces the original field values.
	merged, err := MergeSecrets(redacted, secretsJSON)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(merged, &got))
	assert.Equal(t, "s3cr3t", got["password"])
	assert.Equal(t, "SiteWideBmcRoot", got["credentialType"])
	assert.Equal(t, "aa:bb", got["macAddress"])
}

func TestRedactSecretsMultipleFieldsSkipsAbsentOnes(t *testing.T) {
	orig := []byte(`{"name":"run-1","password":"s3cr3t","token":"t0ken"}`)

	redacted, secretsJSON, err := RedactSecrets(orig, []string{"password", "token", "absent"})
	require.NoError(t, err)

	assert.NotContains(t, string(redacted), "s3cr3t")
	assert.NotContains(t, string(redacted), "t0ken")

	var secrets map[string]any
	require.NoError(t, json.Unmarshal(secretsJSON, &secrets))
	assert.Equal(t, map[string]any{"password": "s3cr3t", "token": "t0ken"}, secrets)
}

func TestRedactSecretsWithoutMatchingFields(t *testing.T) {
	orig := []byte(`{"credentialType":"SiteWideBmcRoot"}`)

	redacted, secretsJSON, err := RedactSecrets(orig, nil)
	require.NoError(t, err)
	assert.Equal(t, orig, redacted)
	assert.Nil(t, secretsJSON)

	// A named field that is absent yields no secrets and leaves the input intact.
	redacted, secretsJSON, err = RedactSecrets(orig, []string{"password"})
	require.NoError(t, err)
	assert.Equal(t, orig, redacted)
	assert.Nil(t, secretsJSON)
}

func TestRedactSecretsRejectsNonObjectPayload(t *testing.T) {
	_, _, err := RedactSecrets([]byte(`["not-an-object"]`), []string{"password"})
	require.Error(t, err)
}

func TestMergeEmptySecrets(t *testing.T) {
	redacted := []byte(`{"credentialType":"SiteWideBmcRoot"}`)
	out, err := MergeSecrets(redacted, nil)
	require.NoError(t, err)
	assert.Equal(t, redacted, out)
}
