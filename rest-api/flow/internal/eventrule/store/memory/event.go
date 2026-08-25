// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	converterdao "github.com/NVIDIA/infra-controller/rest-api/flow/internal/converter/dao"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
)

// Events returns stable event snapshots for diagnostics and tests without
// recording another source observation.
func (s *Store) Events() ([]eventrule.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]eventrule.Event, 0, len(s.events))
	for id := range s.events {
		event, err := s.event(id)
		if err != nil {
			return nil, err
		}

		result = append(result, *event)
	}

	slices.SortFunc(result, func(a, b eventrule.Event) int {
		return cmp.Compare(a.ID.String(), b.ID.String())
	})

	return result, nil
}

// ObserveEvent returns and records an existing source event. A missing event
// is represented by (nil, nil).
func (s *Store) ObserveEvent(
	_ context.Context,
	key eventrule.EventKey,
) (*eventrule.Event, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id, exists := s.eventsByKey[key]
	if !exists {
		return nil, nil
	}

	event, err := s.event(id)
	if err != nil {
		return nil, err
	}

	event.Observations++
	now := s.now().UTC()

	if now.After(event.LastObservedAt) {
		event.LastObservedAt = now
	}

	if err := s.setEvent(event); err != nil {
		return nil, err
	}

	return s.event(id)
}

// CreateEvent inserts and returns a durable event. A concurrent duplicate
// records another observation and returns (nil, nil).
func (s *Store) CreateEvent(
	_ context.Context,
	definition eventrule.Event,
) (*eventrule.Event, error) {
	if err := definition.ValidateDefinition(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().UTC()

	if id, exists := s.eventsByKey[definition.Key]; exists {
		event, err := s.event(id)
		if err != nil {
			return nil, err
		}

		event.Observations++

		if now.After(event.LastObservedAt) {
			event.LastObservedAt = now
		}

		if err := s.setEvent(event); err != nil {
			return nil, err
		}

		return nil, nil
	}

	event, err := eventrule.NewEvent(definition, now)
	if err != nil {
		return nil, err
	}

	persisted, err := converterdao.EventTo(event)
	if err != nil {
		return nil, err
	}

	s.events[event.ID] = *persisted
	s.eventsByKey[event.Key] = event.ID

	return s.event(event.ID)
}

func (s *Store) event(id uuid.UUID) (*eventrule.Event, error) {
	persisted, exists := s.events[id]
	if !exists {
		return nil, fmt.Errorf("%w: %s", eventrule.ErrEventNotFound, id)
	}

	return converterdao.EventFrom(&persisted)
}

func (s *Store) setEvent(event *eventrule.Event) error {
	if _, exists := s.events[event.ID]; !exists {
		return fmt.Errorf("%w: %s", eventrule.ErrEventNotFound, event.ID)
	}

	persisted, err := converterdao.EventTo(event)
	if err != nil {
		return err
	}

	s.events[event.ID] = *persisted

	return nil
}
