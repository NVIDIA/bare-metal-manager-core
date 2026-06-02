// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/rs/zerolog/log"
)

// CreateHash takes a string and returns SHA 256 digest in a byte array
func CreateHash(key string) []byte {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(key))
	if err != nil {
		log.Panic().Err(err).Msg("error calculating hash for data en/decryption")
	}

	return hasher.Sum(nil)
}

// EncryptData provides mechanism to encrypt arguments being passed into workflows
// so it is not visible within Temporal system
func EncryptData(data []byte, passphrase string) []byte {
	key := CreateHash(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic().Err(err).Msg("failed to decrypt data, could not create cipher block")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic().Err(err).Msg("failed to encrypt data, could not create GCM wrapped cipher block")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Panic().Err(err).Msg("failed to encrypt data, could not create nonce")
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// DecryptData provides mechanism to decrypt arguments being passed into workflows
func DecryptData(data []byte, passphrase string) []byte {
	key := CreateHash(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic().Err(err).Msg("failed to decrypt data, could not create cipher block")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic().Err(err).Msg("failed to decrypt data, could not create GCM wrapped cipher block")
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}
