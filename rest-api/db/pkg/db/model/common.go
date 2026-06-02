// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

var protoJsonUnmarshalOptions = protojson.UnmarshalOptions{
	AllowPartial:   true,
	DiscardUnknown: true,
}

// Labels is the canonical entity-side representation of a workflow
// `Metadata.Labels` list — a key/value map that can be round-tripped
// through `ToProto` / `FromProtoMetadata` without losing the empty
// vs. nil distinction. Defining a named type lets us hang the proto
// conversion on it as a method (`labels.ToProto()`) rather than
// keeping a free function in this package.
type Labels map[string]string

// ToProto converts the labels into the workflow proto repeated Label
// representation. Returns nil for a nil map; an empty map yields a
// non-nil empty slice so callers can distinguish "labels explicitly
// cleared" from "no labels at all".
func (l Labels) ToProto() []*cwssaws.Label {
	if l == nil {
		return nil
	}
	protoLabels := make([]*cwssaws.Label, 0, len(l))
	for k, v := range l {
		protoLabels = append(protoLabels, &cwssaws.Label{
			Key:   k,
			Value: &v,
		})
	}
	return protoLabels
}

// FromProto populates the receiver from a workflow proto repeated Label
// representation, mirroring `(Labels).ToProto()`. A nil input clears the
// receiver to nil; a non-nil but empty input yields a non-nil empty map,
// so callers can distinguish "no labels reported" from "labels explicitly
// cleared". Entries with an empty key are skipped; a label with a nil
// value resolves to an empty string.
func (l *Labels) FromProto(protoLabels []*cwssaws.Label) {
	if protoLabels == nil {
		*l = nil
		return
	}
	result := Labels{}
	for _, label := range protoLabels {
		if label == nil || label.Key == "" {
			continue
		}
		value := ""
		if label.Value != nil {
			value = *label.Value
		}
		result[label.Key] = value
	}
	*l = result
}
