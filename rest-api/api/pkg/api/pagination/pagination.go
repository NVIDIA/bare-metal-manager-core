// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package pagination

import (
	"fmt"
	"regexp"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbp "github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
)

const (
	// MaxPageSize is the maximum page size allowed
	MaxPageSize = 100

	// ResponseHeaderName describes the header name for the pagination response
	ResponseHeaderName = "X-Pagination"
)

var (
	// OrderByRegex is the regex for the orderBy field
	OrderByRegex = fmt.Sprintf("^[A-Z0-9_]+_(%v|%v)$", cdbp.OrderAscending, cdbp.OrderDescending)
)

// PageRequest captures and validates pagination data
type PageRequest struct {
	// Name is the name of the Allocation
	PageNumber *int `query:"pageNumber"`
	// Description is the description of the Allocation
	PageSize *int `query:"pageSize"`
	// OrderByStr is the order by field
	OrderByStr *string `query:"orderBy"`

	// Offset is the offset of the pagination
	Offset *int
	// Limit is the limit of the pagination
	Limit *int
	// OrderBy is the processed order by field
	OrderBy *cdbp.OrderBy
}

// Validate ensure the values passed in request are acceptable
func (pr *PageRequest) Validate(orderByFields []string) error {
	err := validation.ValidateStruct(pr,
		validation.Field(&pr.PageNumber,
			validation.Min(1).Error("must be greater than 0"),
		),
		validation.Field(&pr.PageSize,
			validation.Min(1).Error("must be greater than 0"),
			validation.Max(MaxPageSize).Error(fmt.Sprintf("must be less that or equal to: %v", MaxPageSize)),
		),
		validation.Field(&pr.OrderByStr,
			validation.Match(regexp.MustCompile(OrderByRegex)).Error(fmt.Sprintf("must be in the format of field_%v or field_%v", cdbp.OrderAscending, cdbp.OrderDescending)),
		),
	)

	if err != nil {
		return err
	}

	if pr.PageNumber == nil || *pr.PageNumber == 0 {
		pr.PageNumber = cdb.GetIntPtr(1)
	}

	if pr.PageSize == nil || *pr.PageSize == 0 {
		pr.PageSize = cdb.GetIntPtr(cdbp.DefaultLimit)
	}

	offset := (*pr.PageNumber - 1) * *pr.PageSize

	pr.Offset = cdb.GetIntPtr(offset)
	pr.Limit = pr.PageSize

	if pr.OrderByStr != nil {
		if orderByFields == nil {
			return fmt.Errorf("orderBy fields must be provided as an argument")
		}

		comps := strings.Split(*pr.OrderByStr, "_")
		compsLen := len(comps)
		if compsLen == 0 {
			return fmt.Errorf("orderBy input %v is not valid", *pr.OrderByStr)
		}
		// last one should be directionality ASC/DESC and everything else is the name
		order := comps[compsLen-1]
		field := strings.ToLower(strings.Join(comps[:compsLen-1], "_"))

		if !cdb.IsStrInSlice(field, orderByFields) {
			return fmt.Errorf("orderBy field %v is not valid", field)
		}

		pr.OrderBy = &cdbp.OrderBy{
			Field: field,
			Order: order,
		}
	}

	return nil
}

// PageResponse is the response for a paginated request
type PageResponse struct {
	// PageNumber is the page number
	PageNumber int `json:"pageNumber"`
	// PageSize is the page size
	PageSize int `json:"pageSize"`
	// Total is the total number of items
	Total int `json:"total"`
	// OrderBy is the order by field
	OrderBy *string `json:"orderBy"`
}

// NewPageResponse creates a new PageResponse
func NewPageResponse(pageNumber int, pageSize int, total int, orderBy *string) *PageResponse {
	return &PageResponse{
		PageNumber: pageNumber,
		PageSize:   pageSize,
		Total:      total,
		OrderBy:    orderBy,
	}
}

func (pr *PageRequest) ConvertToDB() cdbp.PageInput {
	if pr == nil {
		return cdbp.PageInput{}
	}
	return cdbp.PageInput{
		Offset:  pr.Offset,
		Limit:   pr.Limit,
		OrderBy: pr.OrderBy,
	}
}
