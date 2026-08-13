// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewCipher(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr string
	}{
		{name: "valid key", key: "test-key"},
		{name: "empty key", wantErr: "data encryption key is empty"},
		{name: "whitespace key", key: " \n", wantErr: "data encryption key is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := NewCipher(tt.key)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
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
	require.NoError(t, os.WriteFile(validPath, []byte("test-key\n"), 0o600))
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

func TestCipher_EncryptDecrypt(t *testing.T) {
	plaintext := []byte("download-credential")
	cipher, err := NewCipher("test-key")
	require.NoError(t, err)

	first, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)
	second, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	require.NotContains(t, string(first), string(plaintext))

	decrypted, err := cipher.Decrypt(first)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestCipher_Decrypt(t *testing.T) {
	cipher, err := NewCipher("test-key")
	require.NoError(t, err)
	otherCipher, err := NewCipher("other-key")
	require.NoError(t, err)

	ciphertext, err := cipher.Encrypt([]byte("download-credential"))
	require.NoError(t, err)

	tests := []struct {
		name       string
		cipher     *Cipher
		ciphertext []byte
		wantErr    string
	}{
		{name: "wrong key", cipher: otherCipher, ciphertext: ciphertext, wantErr: "decrypt data"},
		{name: "short ciphertext", cipher: cipher, ciphertext: []byte("short"), wantErr: "encrypted data is too short"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := tt.cipher.Decrypt(tt.ciphertext)
			require.ErrorContains(t, err, tt.wantErr)
			require.Nil(t, plaintext)
		})
	}
}
