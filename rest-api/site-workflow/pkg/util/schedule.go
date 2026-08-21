// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"time"

	"github.com/robfig/cron/v3"
)

// scheduleSampleAnchor fixes the instant the interval is measured from, so the result depends
// only on the schedule and not on when the Site Agent happens to start.
var scheduleSampleAnchor = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

// scheduleSampleGaps is how many gaps between fire times to compare. A schedule with uneven
// gaps needs more than one to find the longest.
const scheduleSampleGaps = 4

// InventoryIntervalFromSchedule reports how much time can pass between two inventory
// collections on the given Temporal cron schedule. A cron expression carries no interval
// field, so this measures the gap between consecutive fire times and returns the longest
// one it sees. Cloud uses the result to decide when reported data is stale, and a schedule
// like `0 9,17 * * *` alternates between an 8 and a 16 hour gap, so returning the shorter
// one would call fresh data stale.
func InventoryIntervalFromSchedule(schedule string) (time.Duration, error) {
	// Temporal parses cron schedules with the standard five fields plus descriptors such as
	// `@every 3m`, which is exactly what ParseStandard accepts.
	parsed, err := cron.ParseStandard(schedule)
	if err != nil {
		return 0, err
	}

	longest := time.Duration(0)
	current := parsed.Next(scheduleSampleAnchor)
	for range scheduleSampleGaps {
		next := parsed.Next(current)
		if gap := next.Sub(current); gap > longest {
			longest = gap
		}
		current = next
	}

	return longest, nil
}
