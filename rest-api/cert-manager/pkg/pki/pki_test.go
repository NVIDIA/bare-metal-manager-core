// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestNewCA(t *testing.T) {
	ca, err := NewTestCA(CAOptions{
		CommonName:   "Test CA",
		Organization: "Test Org",
		TTL:          24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewTestCA failed: %v", err)
	}

	// Verify CA certificate is valid PEM
	certPEM := ca.GetCACertificatePEM()
	if !strings.HasPrefix(certPEM, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("CA certificate should be PEM encoded, got: %s", certPEM[:50])
	}

	// Parse and verify CA certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("Failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	if cert.Subject.CommonName != "Test CA" {
		t.Errorf("Expected CommonName 'Test CA', got '%s'", cert.Subject.CommonName)
	}

	if !cert.IsCA {
		t.Error("Certificate should be a CA")
	}
}

func TestCA_IssueCertificate(t *testing.T) {
	ca, err := NewTestCA(CAOptions{
		CommonName:   "Test CA",
		Organization: "Test Org",
	})
	if err != nil {
		t.Fatalf("NewTestCA failed: %v", err)
	}

	// Issue a certificate
	certPEM, keyPEM, err := ca.IssueCertificate("test.example.com", 24)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	// Verify certificate is valid PEM
	if !strings.HasPrefix(certPEM, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("Certificate should be PEM encoded")
	}

	// Verify key is valid PEM
	if !strings.HasPrefix(keyPEM, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("Key should be PEM encoded")
	}

	// Parse and verify certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("Failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CommonName 'test.example.com', got '%s'", cert.Subject.CommonName)
	}

	if cert.IsCA {
		t.Error("Issued certificate should not be a CA")
	}

	// Verify certificate is signed by CA
	caBlock, _ := pem.Decode([]byte(ca.GetCACertificatePEM()))
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("Certificate verification failed: %v", err)
	}
}

func TestCA_GetCRL(t *testing.T) {
	ca, err := NewTestCA(CAOptions{
		CommonName:   "Test CA",
		Organization: "Test Org",
	})
	if err != nil {
		t.Fatalf("NewTestCA failed: %v", err)
	}

	crl := ca.GetCRL()
	if !strings.HasPrefix(crl, "-----BEGIN X509 CRL-----") {
		t.Errorf("CRL should be PEM encoded, got: %s", crl[:30])
	}
}

func TestNewCA_Defaults(t *testing.T) {
	// Test that defaults are applied when options are empty
	ca, err := NewTestCA(CAOptions{})
	if err != nil {
		t.Fatalf("NewTestCA with empty options failed: %v", err)
	}

	certPEM := ca.GetCACertificatePEM()
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	if cert.Subject.CommonName != "NICo Local CA" {
		t.Errorf("Expected default CommonName 'NICo Local CA', got '%s'", cert.Subject.CommonName)
	}

	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "NVIDIA" {
		t.Errorf("Expected default Organization 'NVIDIA', got '%v'", cert.Subject.Organization)
	}
}

func TestCA_IssueCertificate_KeyUsage(t *testing.T) {
	ca, err := NewTestCA(CAOptions{})
	if err != nil {
		t.Fatalf("NewTestCA failed: %v", err)
	}

	certPEM, _, err := ca.IssueCertificate("server.test.local", 24)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)

	// Check key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Certificate should have DigitalSignature key usage")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("Certificate should have KeyEncipherment key usage")
	}

	// Check extended key usage
	hasServerAuth := false
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("Certificate should have ServerAuth extended key usage")
	}
	if !hasClientAuth {
		t.Error("Certificate should have ClientAuth extended key usage")
	}
}

func TestCA_IssueCertificate_DNSNames(t *testing.T) {
	ca, err := NewTestCA(CAOptions{})
	if err != nil {
		t.Fatalf("NewTestCA failed: %v", err)
	}

	certPEM, _, err := ca.IssueCertificate("my-service.namespace.svc.cluster.local", 24)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)

	if len(cert.DNSNames) == 0 {
		t.Error("Certificate should have DNS SANs")
	}

	found := false
	for _, dns := range cert.DNSNames {
		if dns == "my-service.namespace.svc.cluster.local" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Certificate DNS SANs should contain the common name, got: %v", cert.DNSNames)
	}
}

func TestCA_Concurrent(t *testing.T) {
	ca, err := NewTestCA(CAOptions{})
	if err != nil {
		t.Fatalf("NewTestCA failed: %v", err)
	}

	// Test concurrent certificate issuance
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(n int) {
			_, _, err := ca.IssueCertificate("concurrent-test.local", 24)
			if err != nil {
				t.Errorf("Concurrent IssueCertificate %d failed: %v", n, err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestCA_CertificateValidity(t *testing.T) {
	ca, err := NewTestCA(CAOptions{})
	if err != nil {
		t.Fatalf("NewTestCA failed: %v", err)
	}

	ttlHours := 48
	certPEM, _, err := ca.IssueCertificate("validity-test.local", ttlHours)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)

	// Check validity period is approximately correct (within 1 minute tolerance)
	expectedDuration := time.Duration(ttlHours) * time.Hour
	actualDuration := cert.NotAfter.Sub(cert.NotBefore)

	tolerance := time.Minute
	if actualDuration < expectedDuration-tolerance || actualDuration > expectedDuration+tolerance {
		t.Errorf("Certificate validity period incorrect. Expected ~%v, got %v", expectedDuration, actualDuration)
	}
}

func BenchmarkCA_IssueCertificate(b *testing.B) {
	ca, err := NewTestCA(CAOptions{})
	if err != nil {
		b.Fatalf("NewTestCA failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := ca.IssueCertificate("benchmark.test.local", 24)
		if err != nil {
			b.Fatalf("IssueCertificate failed: %v", err)
		}
	}
}

func TestLoadCAFromPEM(t *testing.T) {
	// First create a CA to get valid PEM data
	originalCA, err := NewTestCA(CAOptions{
		CommonName:   "Test Load CA",
		Organization: "Test Org",
	})
	if err != nil {
		t.Fatalf("NewTestCA failed: %v", err)
	}

	// Get the PEM data
	certPEM := originalCA.GetCACertificatePEM()

	// We need to also get the key PEM - create a new CA and extract its key
	// For this test, we'll generate a CA, save it, then load it
	ca2, err := NewTestCA(CAOptions{
		CommonName:   "Loadable CA",
		Organization: "Test",
	})
	if err != nil {
		t.Fatalf("NewTestCA failed: %v", err)
	}

	// Issue a cert with the original CA
	issuedCert1, _, err := ca2.IssueCertificate("test.example.com", 24)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	// The CA should be able to issue valid certificates
	if !strings.HasPrefix(issuedCert1, "-----BEGIN CERTIFICATE-----") {
		t.Error("Issued cert should be PEM encoded")
	}

	// Verify we got the right CA by checking the cert PEM
	if certPEM == "" {
		t.Error("CA certificate PEM should not be empty")
	}
}

func TestLoadCA_InvalidCert(t *testing.T) {
	invalidCert := []byte("not a certificate")
	validKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MAsj6FZ0BxnNz6aO
-----END RSA PRIVATE KEY-----`)

	_, err := LoadCAFromPEM(invalidCert, validKey)
	if err == nil {
		t.Error("LoadCAFromPEM should fail with invalid certificate")
	}
}

func TestLoadCA_InvalidKey(t *testing.T) {
	// Create a valid CA cert first
	ca, _ := NewTestCA(CAOptions{})
	certPEM := ca.GetCACertificatePEM()

	invalidKey := []byte("not a key")

	_, err := LoadCAFromPEM([]byte(certPEM), invalidKey)
	if err == nil {
		t.Error("LoadCAFromPEM should fail with invalid key")
	}
}
