// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testKey      = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	otherTestKey = "YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODk="
)

func TestNewCipher(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		wantErrPart string
	}{
		{name: "valid key", key: testKey},
		{name: "empty key", wantErrPart: "data encryption key is empty"},
		{name: "whitespace key", key: " \n", wantErrPart: "data encryption key is empty"},
		{name: "invalid base64", key: "not-base64", wantErrPart: "data encryption key must be base64 encoded"},
		{name: "short decoded key", key: base64.StdEncoding.EncodeToString([]byte("short")), wantErrPart: "data encryption key must decode to exactly 32 bytes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := NewCipher(tt.key)
			if tt.wantErrPart != "" {
				require.ErrorContains(t, err, tt.wantErrPart)
				require.Nil(t, cipher)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cipher)
		})
	}
}

func TestNewCipherFromFile(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid-key")
	require.NoError(t, os.WriteFile(validPath, []byte(testKey+"\n"), 0o600))
	emptyPath := filepath.Join(dir, "empty-key")
	require.NoError(t, os.WriteFile(emptyPath, []byte(" \n"), 0o600))

	tests := []struct {
		name        string
		path        string
		wantErrPart string
	}{
		{name: "valid key", path: validPath},
		{name: "missing file", path: filepath.Join(dir, "missing-key"), wantErrPart: "read data encryption key"},
		{name: "empty file", path: emptyPath, wantErrPart: "data encryption key is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := NewCipherFromFile(tt.path)
			if tt.wantErrPart != "" {
				require.ErrorContains(t, err, tt.wantErrPart)
				require.Nil(t, cipher)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cipher)
		})
	}
}

func TestCipher_Encrypt(t *testing.T) {
	plaintext := []byte("download-credential")
	additionalData := []byte("firmware-auth:task-123")
	cipher, err := NewCipher(testKey)
	require.NoError(t, err)

	first, err := cipher.Encrypt(plaintext, additionalData)
	require.NoError(t, err)
	second, err := cipher.Encrypt(plaintext, additionalData)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	require.NotContains(t, string(first), string(plaintext))

	decrypted, err := cipher.Decrypt(first, additionalData)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	ciphertext, err := cipher.Encrypt(plaintext, nil)
	require.EqualError(t, err, "additional authenticated data is empty")
	require.Nil(t, ciphertext)
}

func TestCipher_Decrypt(t *testing.T) {
	additionalData := []byte("firmware-auth:task-123")
	cipher, err := NewCipher(testKey)
	require.NoError(t, err)
	otherCipher, err := NewCipher(otherTestKey)
	require.NoError(t, err)

	ciphertext, err := cipher.Encrypt([]byte("download-credential"), additionalData)
	require.NoError(t, err)
	tamperedCiphertext := append([]byte(nil), ciphertext...)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 1

	tests := []struct {
		name           string
		cipher         *Cipher
		ciphertext     []byte
		additionalData []byte
		wantErr        string
	}{
		{name: "wrong key", cipher: otherCipher, ciphertext: ciphertext, additionalData: additionalData, wantErr: "decrypt data"},
		{name: "wrong additional data", cipher: cipher, ciphertext: ciphertext, additionalData: []byte("firmware-auth:task-456"), wantErr: "decrypt data"},
		{name: "empty additional data", cipher: cipher, ciphertext: ciphertext, wantErr: "additional authenticated data is empty"},
		{name: "short ciphertext", cipher: cipher, ciphertext: []byte("short"), additionalData: additionalData, wantErr: "encrypted data is too short"},
		{name: "tampered ciphertext", cipher: cipher, ciphertext: tamperedCiphertext, additionalData: additionalData, wantErr: "decrypt data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := tt.cipher.Decrypt(tt.ciphertext, tt.additionalData)
			require.ErrorContains(t, err, tt.wantErr)
			require.Nil(t, plaintext)
		})
	}
}
