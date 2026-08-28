// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestObfuscateRequestBody(t *testing.T) {
	body := map[string]interface{}{
		"siteId": "site-1",
		"authenticationData": map[string]interface{}{
			"shared": "download-token",
		},
	}

	obfuscateRequestBody(body)

	assert.Equal(t, "site-1", body["siteId"])
	assert.Equal(t, auditObfuscatedValue, body["authenticationData"])
}
