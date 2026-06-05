// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestGetSearchQuery(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		want  string
		isNil bool
	}{
		{
			name:  "absent query",
			path:  "/test",
			isNil: true,
		},
		{
			name:  "empty query",
			path:  "/test?query=",
			isNil: true,
		},
		{
			name:  "whitespace only",
			path:  "/test?query=%20%20%20",
			isNil: true,
		},
		{
			name: "normal query",
			path: "/test?query=abc",
			want: "abc",
		},
		{
			name: "leading and trailing whitespace",
			path: "/test?query=%20abc%20",
			want: "abc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			got := GetSearchQuery(c)
			if tt.isNil {
				assert.Nil(t, got)
				return
			}

			if assert.NotNil(t, got) {
				assert.Equal(t, tt.want, *got)
			}
		})
	}
}
