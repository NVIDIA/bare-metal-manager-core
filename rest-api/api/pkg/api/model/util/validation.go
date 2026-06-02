// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"

	"github.com/google/uuid"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

var (
	LeadingWhitespaceRegexp  = regexp.MustCompile("^\\s+.*")
	TrailingWhitespaceRegexp = regexp.MustCompile(".*\\s+$")
	NotAllWhitespaceRegexp   = regexp.MustCompile("[^\\s]+")
	ShaHashRegex             = regexp.MustCompile("^[A-Fa-f0-9]+$")
	DiskImagePathRegex       = regexp.MustCompile("^/dev/(:?nvme\\d+n\\d+|sd*)")

	ValidationErrorNameHasLeadingWhitespace  = errors.New("name field has leading whitespace")
	ValidationErrorNameHasTrailingWhitespace = errors.New("name field has trailing whitespace")
	ValidationErrorNameFieldIsEmpty          = errors.New("name field is empty")
	ValidationErrorOnlyWhitespace            = errors.New("field consists only of whitespace")

	// Label restrictions
	LabelKeyMaxLength   = 255
	LabelValueMaxLength = 255
	LabelCountMax       = 10

	// Label validation error messages
	ErrValidationLabelKeyEmpty    = errors.New("one or more labels do not have a key specified")
	ErrValidationLabelKeyLength   = fmt.Errorf("label key must contain at least 1 character and a maximum of %v characters", LabelKeyMaxLength)
	ErrValidationLabelValueLength = fmt.Errorf("label value cannot exceed a maximum of %v characters", LabelValueMaxLength)
	ErrValidationLabelCount       = fmt.Errorf("up to %v key/value pairs can be specified in labels", LabelCountMax)
)

// ValidateLabels validates optional API label maps (count, keys, values).
// Signature matches ozzo's `validation.RuleFunc` so it can be used
// directly inside a `validation.By(...)` call from a struct's `Validate`.
// Returns nil when labels is nil; ignores values that aren't a
// `map[string]string`.
func ValidateLabels(value interface{}) error {
	if value == nil {
		return nil
	}
	labels, ok := value.(map[string]string)
	if !ok {
		return nil
	}
	if labels == nil {
		return nil
	}
	if len(labels) > LabelCountMax {
		return validation.Errors{
			"labels": ErrValidationLabelCount,
		}
	}

	keyErrMsg := ErrValidationLabelKeyLength.Error()
	valueErrMsg := ErrValidationLabelValueLength.Error()

	for key, value := range labels {
		if key == "" {
			return validation.Errors{
				"labels": ErrValidationLabelKeyEmpty,
			}
		}

		err := validation.Validate(key,
			validation.Match(NotAllWhitespaceRegexp).Error("label key consists only of whitespace"),
			validation.Length(1, LabelKeyMaxLength).Error(keyErrMsg),
		)
		if err != nil {
			return validation.Errors{
				"labels": err,
			}
		}

		err = validation.Validate(value,
			validation.When(value != "",
				validation.Length(0, LabelValueMaxLength).Error(valueErrMsg),
			),
		)
		if err != nil {
			return validation.Errors{
				"labels": err,
			}
		}
	}

	return nil
}

// util.GetUUIDPtrToStrPtr is a utility function to return string pointer from uuid pointer
func GetUUIDPtrToStrPtr(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

// ValidateNested is a utility function to validate nested struct
func ValidateNested(target interface{}, fieldRules ...*validation.FieldRules) *validation.FieldRules {
	if target == nil {
		return nil
	}

	return validation.Field(target, validation.By(func(value interface{}) error {
		valueV := reflect.Indirect(reflect.ValueOf(value))
		if valueV.CanAddr() {
			addr := valueV.Addr().Interface()
			return validation.ValidateStruct(addr, fieldRules...)
		}
		return validation.ValidateStruct(target, fieldRules...)
	}))
}

// ValidateNameCharacters is a utility function to lexically validate the name field
// Currently checks for leading or trailing whitespaces
// NOTE: Can only be used in conjunction with validation.Required or with validation.When(name != nil, validation.By(util.ValidateNameCharacters))
func ValidateNameCharacters(value interface{}) error {
	s, ok := value.(string)
	var name string
	if !ok {
		// check for string pointer
		sPtr, ok := value.(*string)
		if !ok {
			return errors.New("value in name field must be a string type")
		}
		if sPtr == nil {
			return errors.New("name field cannot be nil")
		}
		name = *sPtr
	} else {
		name = s
	}
	if LeadingWhitespaceRegexp.Match([]byte(name)) {
		return ValidationErrorNameHasLeadingWhitespace
	}
	if TrailingWhitespaceRegexp.Match([]byte(name)) {
		return ValidationErrorNameHasTrailingWhitespace
	}
	return nil
}

// IsNilOrEmptyStrPtr is a utility function to check if the string pointer is nil or the underlying value is empty
func IsNilOrEmptyStrPtr(s *string) bool {
	return s == nil || *s == ""
}

// IsEmptyStrPtr is a utility function to check if the underlying value of a string pointer is empty
func IsEmptyStrPtr(s *string) bool {
	return s != nil && *s == ""
}
