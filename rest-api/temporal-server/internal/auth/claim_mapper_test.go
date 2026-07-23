// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.temporal.io/server/common/authorization"
	"google.golang.org/grpc/credentials"
)

func TestClaimMapperMapsVerifiedCertificates(t *testing.T) {
	t.Parallel()

	siteID := "11111111-1111-1111-1111-111111111111"
	tests := []struct {
		name          string
		certificate   *x509.Certificate
		verified      bool
		wantKind      identityKind
		wantNamespace string
	}{
		{name: "missing certificate", wantKind: identityUnknown},
		{
			name:        "unverified certificate",
			certificate: certificate(clientCommonName, controlDNSName),
			wantKind:    identityUnknown,
		},
		{
			name:        "interservice certificate",
			certificate: certificate("", adminDNSName),
			verified:    true,
			wantKind:    identityAdmin,
		},
		{
			name:        "control certificate",
			certificate: certificate(clientCommonName, clientCommonName, controlDNSName, "cloud-worker", "site-worker"),
			verified:    true,
			wantKind:    identityControl,
		},
		{
			name:        "flow certificate",
			certificate: certificate(clientCommonName, clientCommonName, flowDNSName),
			verified:    true,
			wantKind:    identityFlow,
		},
		{
			name:          "site certificate",
			certificate:   certificate(siteID+siteClientDNSSuffix, siteID+siteClientDNSSuffix),
			verified:      true,
			wantKind:      identitySite,
			wantNamespace: siteID,
		},
		{
			name:        "site certificate without matching SAN",
			certificate: certificate(siteID+siteClientDNSSuffix, "other.client.nico.local"),
			verified:    true,
			wantKind:    identityUnknown,
		},
		{
			name:        "unknown certificate",
			certificate: certificate("unknown", "unknown.client.nico.local"),
			verified:    true,
			wantKind:    identityUnknown,
		},
	}

	mapper := NewClaimMapper()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claims, err := mapper.GetClaims(authInfo(test.certificate, test.verified))
			require.NoError(t, err)
			mappedIdentity, ok := claims.Extensions.(identity)
			require.True(t, ok, "GetClaims() extension type = %T", claims.Extensions)
			assert.Equal(t, test.wantKind, mappedIdentity.kind)
			assert.Equal(t, test.wantNamespace, mappedIdentity.siteNamespace)
		})
	}
}

func certificate(commonName string, dnsNames ...string) *x509.Certificate {
	return &x509.Certificate{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: dnsNames,
	}
}

func authInfo(cert *x509.Certificate, verified bool) *authorization.AuthInfo {
	if cert == nil {
		return nil
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if verified {
		state.VerifiedChains = [][]*x509.Certificate{{cert}}
	}
	return &authorization.AuthInfo{TLSConnection: &credentials.TLSInfo{State: state}}
}
