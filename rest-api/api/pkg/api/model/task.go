// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/pagination"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
)

var ProtoToAPITaskStatusName = map[flowv1.TaskStatus]string{
	flowv1.TaskStatus_TASK_STATUS_UNKNOWN:    "Unknown",
	flowv1.TaskStatus_TASK_STATUS_PENDING:    "Pending",
	flowv1.TaskStatus_TASK_STATUS_RUNNING:    "Running",
	flowv1.TaskStatus_TASK_STATUS_COMPLETED:  "Succeeded",
	flowv1.TaskStatus_TASK_STATUS_FAILED:     "Failed",
	flowv1.TaskStatus_TASK_STATUS_TERMINATED: "Terminated",
	flowv1.TaskStatus_TASK_STATUS_WAITING:    "Waiting",
}

// APITask is the API response model for a Flow-scheduled task
// (OpenAPI schema Task). It covers both rack- and tray-scoped tasks
// because Flow drives them through the same Task entity.
type APITask struct {
	ID          string           `json:"id"`
	Status      string           `json:"status"`
	Description string           `json:"description"`
	Message     string           `json:"message"`
	Started     *time.Time       `json:"started"`
	Finished    *time.Time       `json:"finished"`
	Created     time.Time        `json:"created"`
	Updated     time.Time        `json:"updated"`
	Report      *json.RawMessage `json:"report,omitempty"`
}

// APITaskOption configures optional fields populated on an APITask.
// Used by NewAPITask so list endpoints can omit large optional payloads
// (Report in particular) by default while single-task endpoints opt in.
type APITaskOption func(*apiTaskOptions)

type apiTaskOptions struct {
	withReport bool
}

// WithReport populates APITask.Report from Task.report when the proto
// field is non-empty. Without this option, Report is left nil and is
// omitted from the JSON response.
func WithReport() APITaskOption {
	return func(o *apiTaskOptions) { o.withReport = true }
}

// BuildAPITaskOptions translates the opt-in toggles on an
// APIGetTasksRequest into the APITaskOption slice the list-task
// handlers pass to NewAPITask. Centralized so new opt-in fields
// only need wiring in one place rather than in each list handler.
func BuildAPITaskOptions(req APIGetTasksRequest) []APITaskOption {
	var opts []APITaskOption
	if req.IncludeReport {
		opts = append(opts, WithReport())
	}
	return opts
}

func (t *APITask) FromProto(task *flowv1.Task, opts ...APITaskOption) {
	if task == nil {
		return
	}
	o := apiTaskOptions{}
	for _, opt := range opts {
		opt(&o)
	}
	if task.GetId() != nil {
		t.ID = task.GetId().GetId()
	}
	t.Status = enumOr(ProtoToAPITaskStatusName, task.GetStatus(), "Unknown")
	t.Description = task.GetDescription()
	t.Message = task.GetMessage()
	if ts := task.GetStartedAt(); ts != nil {
		v := ts.AsTime().UTC()
		t.Started = &v
	}
	if ts := task.GetFinishedAt(); ts != nil {
		v := ts.AsTime().UTC()
		t.Finished = &v
	}
	t.Created = task.GetCreatedAt().AsTime().UTC()
	t.Updated = task.GetUpdatedAt().AsTime().UTC()
	if o.withReport {
		if r := task.GetReport(); r != "" {
			raw := json.RawMessage(r)
			t.Report = &raw
		}
	}
}

func NewAPITask(task *flowv1.Task, opts ...APITaskOption) *APITask {
	t := &APITask{}
	t.FromProto(task, opts...)
	return t
}

// APIGetTaskRequest captures query parameters for getting a task by ID.
type APIGetTaskRequest struct {
	SiteID string `query:"siteId"`
}

func (r *APIGetTaskRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId query parameter is required")
	}
	return nil
}

// APICancelTaskRequest is the request body for cancelling a task by ID.
type APICancelTaskRequest struct {
	SiteID string `json:"siteId"`
}

// Validate validates the cancel task request
func (r *APICancelTaskRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId is required")
	}
	return nil
}

// APIGetTasksRequest binds query parameters for rack- and tray-scoped task list
// endpoints. Pagination is bound separately via pagination.PageRequest.
type APIGetTasksRequest struct {
	SiteID        string `query:"siteId"`
	ActiveOnly    bool   `query:"activeOnly"`
	IncludeReport bool   `query:"includeReport"`
}

func (r *APIGetTasksRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId query parameter is required")
	}
	return nil
}

// QueryValues returns query parameters that participate in deterministic
// workflow ID hashing, including pagination fields so concurrent requests
// for different pages do not reuse the same workflow execution.
func (r *APIGetTasksRequest) QueryValues(page pagination.PageRequest) url.Values {
	v := url.Values{}
	v.Set("siteId", r.SiteID)
	if r.ActiveOnly {
		v.Set("activeOnly", strconv.FormatBool(r.ActiveOnly))
	}
	if r.IncludeReport {
		v.Set("includeReport", strconv.FormatBool(r.IncludeReport))
	}
	if page.PageNumber != nil && *page.PageNumber != 0 {
		v.Set("pageNumber", strconv.Itoa(*page.PageNumber))
	}
	if page.PageSize != nil && *page.PageSize != 0 {
		v.Set("pageSize", strconv.Itoa(*page.PageSize))
	}
	return v
}
