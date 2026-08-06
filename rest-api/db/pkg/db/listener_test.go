// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSessionListen(t *testing.T) {
	dbSession := testTxGetTestSession(t)
	defer dbSession.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const channel = "listener_test_channel"
	wakes := make(chan struct{}, 4)
	go dbSession.Listen(ctx, channel, func() { wakes <- struct{}{} })

	// Subscribing wakes the caller once unconditionally, because notifications
	// emitted while unsubscribed are lost. Waiting for it also guarantees the
	// LISTEN below is already in effect, so the notification cannot be missed.
	waitForWake(t, wakes, "initial wake after subscribing")

	_, err := dbSession.DB.Exec("SELECT pg_notify(?, '')", channel)
	require.NoError(t, err)
	waitForWake(t, wakes, "wake after notification")
}

func waitForWake(t *testing.T, wakes <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-wakes:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}
