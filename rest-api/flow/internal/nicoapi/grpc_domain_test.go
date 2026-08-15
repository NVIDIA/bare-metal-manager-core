// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

func TestNVLinkDomainMembershipsFromSwitches(t *testing.T) {
	domainID := "20000000-0000-0000-0000-000000000001"
	switchWithDomain := func(switchID, rackID string) *corev1.Switch {
		return &corev1.Switch{
			Id:               &corev1.SwitchId{Id: switchID},
			RackId:           &corev1.RackId{Id: rackID},
			NvlinkDomainUuid: &corev1.NVLinkDomainId{Value: domainID},
		}
	}

	tests := []struct {
		name      string
		requested []*corev1.SwitchId
		switches  []*corev1.Switch
		want      []NVLinkDomainMembership
		wantErr   string
	}{
		{
			name:      "returns duplicate rack observations",
			requested: []*corev1.SwitchId{{Id: "switch-a"}, {Id: "switch-b"}},
			switches: []*corev1.Switch{
				switchWithDomain("switch-a", "rack-a"),
				switchWithDomain("switch-b", "rack-a"),
			},
			want: []NVLinkDomainMembership{
				{DomainID: domainID, RackID: "rack-a"},
				{DomainID: domainID, RackID: "rack-a"},
			},
		},
		{
			name:      "skips switch without domain observation",
			requested: []*corev1.SwitchId{{Id: "switch-a"}},
			switches: []*corev1.Switch{
				{Id: &corev1.SwitchId{Id: "switch-a"}, RackId: &corev1.RackId{Id: "rack-a"}},
			},
			want: []NVLinkDomainMembership{},
		},
		{
			name:      "skips switch without rack assignment",
			requested: []*corev1.SwitchId{{Id: "switch-a"}},
			switches: []*corev1.Switch{
				{Id: &corev1.SwitchId{Id: "switch-a"}, NvlinkDomainUuid: &corev1.NVLinkDomainId{Value: domainID}},
			},
			want: []NVLinkDomainMembership{},
		},
		{
			name:      "rejects partial details response",
			requested: []*corev1.SwitchId{{Id: "switch-a"}, {Id: "switch-b"}},
			switches:  []*corev1.Switch{switchWithDomain("switch-a", "rack-a")},
			wantErr:   "omitted active switch switch-b",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := nvLinkDomainMembershipsFromSwitches(test.requested, test.switches)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}
