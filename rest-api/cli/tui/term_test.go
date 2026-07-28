// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package tui

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadKey_LoneEscapeReturnsWithoutWaitingForMoreInput(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})

	originalStdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = originalStdin
	})

	result := make(chan KeyEvent, 1)
	readErr := make(chan error, 1)
	go func() {
		key, err := ReadKey()
		if err != nil {
			readErr <- err
			return
		}
		result <- key
	}()

	_, err = writer.Write([]byte{KeyEscape})
	require.NoError(t, err)

	select {
	case key := <-result:
		assert.Equal(t, KeyEvent{Char: KeyEscape}, key)
	case err := <-readErr:
		require.NoError(t, err)
	case <-time.After(500 * time.Millisecond):
		_ = writer.Close()
		t.Fatal("lone Escape did not return before the timeout")
	}
}

func TestReadKey_StillRecognizesArrowEscapeSequences(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})

	originalStdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = originalStdin
	})

	_, err = writer.Write([]byte{KeyEscape, '[', 'A'})
	require.NoError(t, err)

	key, err := ReadKey()
	require.NoError(t, err)
	assert.Equal(t, KeyEvent{Special: KeyUp}, key)
}
