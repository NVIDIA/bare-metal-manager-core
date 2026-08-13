// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package secret encrypts sensitive Flow data before it is persisted or sent
// through Temporal.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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

// NewCipher derives an AES-256 key from key and constructs a Cipher.
func NewCipher(key string) (*Cipher, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, errors.New("data encryption key is empty")
	}

	digest := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(digest[:])
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

// Encrypt returns nonce-prefixed AES-GCM ciphertext.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("generate data encryption nonce: %w", err)
	}

	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt opens nonce-prefixed AES-GCM ciphertext.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("encrypted data is too short")
	}

	nonce := ciphertext[:nonceSize]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	return plaintext, nil
}
