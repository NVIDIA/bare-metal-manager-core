// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import "errors"

// ErrTerminalProcessing identifies an event-processing failure that cannot
// succeed by delivering the same envelope again.
var ErrTerminalProcessing = errors.New("terminal event processing error")
