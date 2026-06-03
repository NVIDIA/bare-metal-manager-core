// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

// IntPtrToUint32Ptr converts a `*int` to a `*uint32`. nil in, nil out.
// Callers must ensure the int sits in `[0, MaxUint32]`; the cast
// otherwise silently wraps. Under the proto-conversion convention,
// that bound is the responsibility of the request-side `Validate`
// (which rejects negatives and overflow with a 400) on the
// API-inbound path, or guaranteed by construction on the proto-inbound
// path (where values originate from a proto `uint32` field).
func IntPtrToUint32Ptr(i *int) *uint32 {
	if i == nil {
		return nil
	}
	u := uint32(*i) //nolint:gosec // bounded upstream by Validate / proto-source.
	return &u
}

// Uint32PtrToIntPtr converts a `*uint32` to a `*int`. nil in, nil out.
// The cast is always safe on 64-bit platforms (the only ones we target);
// on a hypothetical 32-bit build it would wrap on values above
// `MaxInt32`. Under the proto-conversion convention this is a trusted
// cast used inside `FromProto` mappers — the upstream value originates
// from a proto `uint32` field, and any bounds checks that would gate it
// belong in `Validate` upstream.
func Uint32PtrToIntPtr(u *uint32) *int {
	if u == nil {
		return nil
	}
	i := int(*u) //nolint:gosec // bounded by uint32 range; safe on 64-bit targets.
	return &i
}
