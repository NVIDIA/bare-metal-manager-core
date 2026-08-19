// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package secret encrypts sensitive Flow data before it is persisted or sent
// through Temporal.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Cipher encrypts and decrypts sensitive data using AES-GCM.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher decodes a base64-encoded 256-bit key and constructs a Cipher.
func NewCipher(key string) (*Cipher, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, errors.New("data encryption key is empty")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("data encryption key must be base64 encoded: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, errors.New("data encryption key must decode to exactly 32 bytes")
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("create data encryption cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create data encryption GCM: %w", err)
	}

	return &Cipher{aead: aead}, nil
}

// NewCipherFromFile reads and trims the key at path before constructing a
// Cipher. Kubernetes Secret volume files may include a trailing newline.
func NewCipherFromFile(path string) (*Cipher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read data encryption key %q: %w", path, err)
	}

	return NewCipher(string(data))
}

// Encrypt returns nonce-prefixed AES-GCM ciphertext bound to additionalData.
// Callers must use stable, record-specific data and limit each key to
// substantially fewer than 2^32 encryptions to keep random-nonce collision risk
// negligible.
func (c *Cipher) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	if len(additionalData) == 0 {
		return nil, errors.New("additional authenticated data is empty")
	}

	nonce := make([]byte, c.aead.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("generate data encryption nonce: %w", err)
	}

	return c.aead.Seal(nonce, nonce, plaintext, additionalData), nil
}

// Decrypt opens nonce-prefixed AES-GCM ciphertext using the same additionalData
// supplied during encryption.
func (c *Cipher) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	if len(additionalData) == 0 {
		return nil, errors.New("additional authenticated data is empty")
	}

	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("encrypted data is too short")
	}

	nonce := ciphertext[:nonceSize]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext[nonceSize:], additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	return plaintext, nil
}
