// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

// IssuerChangedChannel is the notification channel fired by the
// notify_issuer_changed trigger on the issuer table.
const IssuerChangedChannel = "issuer_changed"

const (
	listenBackoffInitial = time.Second
	listenBackoffMax     = 30 * time.Second
)

// Listen subscribes to a PostgreSQL notification channel and invokes onNotify
// after every notification. It blocks until ctx is cancelled, so callers start
// it in its own goroutine.
//
// On connection loss it reconnects with exponential backoff capped at 30s.
// onNotify must be safe to call repeatedly.
func (s *Session) Listen(ctx context.Context, channel string, onNotify func()) {
	backoff := listenBackoffInitial

	for ctx.Err() == nil {
		subscribed, err := s.listenOnce(ctx, channel, onNotify)
		if ctx.Err() != nil {
			return
		}
		if subscribed {
			backoff = listenBackoffInitial
		}

		log.Warn().Err(err).Str("channel", channel).Dur("retryIn", backoff).
			Msg("notification listener disconnected, reconnecting")

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, listenBackoffMax)
	}
}

// listenOnce subscribes on a connection of its own and blocks on notifications
// until the connection fails or ctx is cancelled. It reports whether the
// subscription was established, so the caller can reset its backoff.
//
// The connection is opened outside the pool: a subscription owns its connection
// for its whole lifetime, and holding a pooled one forever would starve the
// pool instead.
func (s *Session) listenOnce(ctx context.Context, channel string, onNotify func()) (bool, error) {
	if s.pool == nil {
		return false, fmt.Errorf("session has no underlying pgx pool")
	}

	conn, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close(context.Background()) }()

	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		return false, err
	}

	// Notifications emitted while this replica was not subscribed are gone, so
	// the state is re-read unconditionally after every successful (re)connect.
	onNotify()

	for {
		if _, err := conn.WaitForNotification(ctx); err != nil {
			return true, err
		}
		onNotify()
	}
}
