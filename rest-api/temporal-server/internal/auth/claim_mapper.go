// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/x509"
	"slices"
	"strings"

	"go.temporal.io/server/common/authorization"
)

const (
	adminDNSName        = "interservice.server.temporal.local"
	clientCommonName    = "temporal-client"
	flowDNSName         = "flow"
	controlDNSName      = "nico-rest-api"
	siteClientDNSSuffix = ".client.nico.local"
)

type identityKind int

const (
	identityUnknown identityKind = iota
	identityAdmin
	identityControl
	identitySite
	identityFlow
)

type identity struct {
	kind          identityKind
	siteNamespace string
}

type claimMapper struct{}

var _ authorization.ClaimMapper = (*claimMapper)(nil)
var _ authorization.ClaimMapperWithAuthInfoRequired = (*claimMapper)(nil)

func NewClaimMapper() authorization.ClaimMapper {
	return &claimMapper{}
}

func (*claimMapper) AuthInfoRequired() bool {
	return false
}

func (*claimMapper) GetClaims(authInfo *authorization.AuthInfo) (*authorization.Claims, error) {
	claims := &authorization.Claims{Namespaces: make(map[string]authorization.Role)}
	certificate := verifiedLeafCertificate(authInfo)
	if certificate == nil {
		claims.Extensions = identity{kind: identityUnknown}
		return claims, nil
	}

	claims.Subject = certificate.Subject.String()
	claims.Extensions = mapIdentity(certificate)
	return claims, nil
}

func verifiedLeafCertificate(authInfo *authorization.AuthInfo) *x509.Certificate {
	if authInfo == nil || authInfo.TLSConnection == nil || len(authInfo.TLSConnection.State.VerifiedChains) == 0 {
		return nil
	}
	verifiedChain := authInfo.TLSConnection.State.VerifiedChains[0]
	if len(verifiedChain) == 0 {
		return nil
	}
	return verifiedChain[0]
}

func mapIdentity(certificate *x509.Certificate) identity {
	if containsDNSName(certificate, adminDNSName) {
		return identity{kind: identityAdmin}
	}
	if certificate.Subject.CommonName == clientCommonName && containsDNSName(certificate, flowDNSName) {
		return identity{kind: identityFlow}
	}
	if certificate.Subject.CommonName == clientCommonName && containsDNSName(certificate, controlDNSName) {
		return identity{kind: identityControl}
	}

	commonName := strings.ToLower(certificate.Subject.CommonName)
	namespace, ok := strings.CutSuffix(commonName, siteClientDNSSuffix)
	if !ok || !isSiteNamespace(namespace) || !containsDNSName(certificate, commonName) {
		return identity{kind: identityUnknown}
	}
	return identity{kind: identitySite, siteNamespace: namespace}
}

func containsDNSName(certificate *x509.Certificate, name string) bool {
	return slices.ContainsFunc(certificate.DNSNames, func(dnsName string) bool {
		return strings.EqualFold(dnsName, name)
	})
}
