// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	appcli "github.com/NVIDIA/infra-controller/rest-api/cli/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCmdSubnetAttachVPCSendsSelectedTargetAndAllowReplace(t *testing.T) {
	for _, test := range []struct {
		name             string
		currentVpcID     string
		targetVpcID      string
		input            string
		wantAllowReplace bool
	}{
		{
			name:             "different target acknowledged",
			currentVpcID:     "vpc-current",
			targetVpcID:      "vpc-target",
			input:            "y\n",
			wantAllowReplace: true,
		},
		{
			name:         "current target is idempotent",
			currentVpcID: "vpc-current",
			targetVpcID:  "vpc-current",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/v2/org/acme/nico/subnet/subnet-1/attach-vpc", r.URL.Path)
				var body map[string]interface{}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				assert.Equal(t, test.targetVpcID, body["vpcId"])
				assert.Equal(t, test.wantAllowReplace, body["allowReplace"])
				w.Header().Set("Content-Type", "application/json")
				_, err := io.WriteString(w, `{"id":"subnet-1","name":"tenant-subnet"}`)
				require.NoError(t, err)
			}))
			defer server.Close()

			session := NewSession(appcli.NewClient(server.URL, "acme", "token", nil, false), "acme", "")
			session.Scope.SiteID = "site-1"
			session.Cache.Set("_tenant", []NamedItem{{Name: "acme", ID: "tenant-1"}})
			session.Cache.Set("subnet", []NamedItem{{
				Name:   "tenant-subnet",
				ID:     "subnet-1",
				Status: "Ready",
				Extra:  map[string]string{"siteId": "site-1", "vpcId": test.currentVpcID},
			}})
			session.Cache.Set("vpc", []NamedItem{{
				Name:   "target-vpc",
				ID:     test.targetVpcID,
				Status: "Ready",
				Extra: map[string]string{
					"networkVirtualizationType": "ETHERNET_VIRTUALIZER",
					"siteId":                    "site-1",
					"tenantId":                  "tenant-1",
				},
			}})

			_, err := withStdin(t, test.input, func() (string, error) {
				return "", cmdSubnetAttachVPC(session, nil)
			})
			require.NoError(t, err)
		})
	}
}
