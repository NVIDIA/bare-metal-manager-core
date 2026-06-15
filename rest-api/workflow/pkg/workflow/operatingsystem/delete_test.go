package operatingsystem

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	osActivity "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/activity/operatingsystem"
)

func expectedSiteHash(siteIDs []uuid.UUID) string {
	siteIDStrings := make([]string, len(siteIDs))
	for i, siteID := range siteIDs {
		siteIDStrings[i] = siteID.String()
	}
	sort.Strings(siteIDStrings)

	h := sha1.New()
	h.Write([]byte(strings.Join(siteIDStrings, "-")))
	return hex.EncodeToString(h.Sum(nil))
}

type DeleteOperatingSystemByIDTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *DeleteOperatingSystemByIDTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *DeleteOperatingSystemByIDTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *DeleteOperatingSystemByIDTestSuite) Test_DeleteOperatingSystemByID_Success() {
	var osManager osActivity.ManageOperatingSystem

	siteID := uuid.New()

	operatingSystemID := uuid.New()

	// Mock DeleteOperatingSystemViaSiteAgent activity
	s.env.RegisterActivity(osManager.DeleteOperatingSystemViaSiteAgent)
	s.env.OnActivity(osManager.DeleteOperatingSystemViaSiteAgent, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// execute DeleteOperatingSystem workflow
	s.env.ExecuteWorkflow(DeleteOperatingSystemByID, []uuid.UUID{siteID}, operatingSystemID)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

// Multi-site happy path: per-site expectations confirm the workflow visits each
// site (and only those). Each is unbounded (no .Once) — successful calls are
// not retried, but unbounded expectations are robust to RetryPolicy interactions.
func (s *DeleteOperatingSystemByIDTestSuite) Test_DeleteOperatingSystemByID_MultiSite_Success() {
	var osManager osActivity.ManageOperatingSystem

	siteIDs := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	operatingSystemID := uuid.New()

	s.env.RegisterActivity(osManager.DeleteOperatingSystemViaSiteAgent)
	for _, sid := range siteIDs {
		s.env.OnActivity(osManager.DeleteOperatingSystemViaSiteAgent, mock.Anything, sid, operatingSystemID).Return(nil)
	}

	s.env.ExecuteWorkflow(DeleteOperatingSystemByID, siteIDs, operatingSystemID)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

// Empty siteIDs: workflow completes without invoking the activity.
func (s *DeleteOperatingSystemByIDTestSuite) Test_DeleteOperatingSystemByID_EmptySites_NoActivity() {
	var osManager osActivity.ManageOperatingSystem

	s.env.RegisterActivity(osManager.DeleteOperatingSystemViaSiteAgent)
	// No expectations registered; the activity must not be called.

	s.env.ExecuteWorkflow(DeleteOperatingSystemByID, []uuid.UUID{}, uuid.New())
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *DeleteOperatingSystemByIDTestSuite) Test_DeleteOperatingSystemByID_ActivityFails() {
	var osManager osActivity.ManageOperatingSystem

	siteID := uuid.New()

	operatingSystemID := uuid.New()

	// Mock DeleteOperatingSystemViaSiteAgent activity failure
	s.env.RegisterActivity(osManager.DeleteOperatingSystemViaSiteAgent)
	s.env.OnActivity(osManager.DeleteOperatingSystemViaSiteAgent, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("DeleteOperatingSystemViaSiteAgent Failure"))

	// execute DeleteOperatingSystemByID workflow
	s.env.ExecuteWorkflow(DeleteOperatingSystemByID, []uuid.UUID{siteID}, operatingSystemID)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal("DeleteOperatingSystemViaSiteAgent Failure", applicationErr.Error())
}

func TestDeleteOperatingSystemByIDSuite(t *testing.T) {
	suite.Run(t, new(DeleteOperatingSystemByIDTestSuite))
}

// ─────────────────────────────────────────────────────────────────────────────
// ExecuteDeleteOperatingSystemByIDWorkflow tests (starter helper)
// ─────────────────────────────────────────────────────────────────────────────

func TestExecuteDeleteOperatingSystemByIDWorkflow_Success(t *testing.T) {
	ctx := context.Background()
	siteIDs := []uuid.UUID{uuid.New(), uuid.New()}
	osID := uuid.New()

	wid := "test-workflow-id"
	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return(wid)

	tc := &tmocks.Client{}
	tc.Mock.On(
		"ExecuteWorkflow",
		ctx,
		mock.AnythingOfType("internal.StartWorkflowOptions"),
		mock.AnythingOfType("func(internal.Context, []uuid.UUID, uuid.UUID) error"),
		siteIDs,
		osID,
	).Return(wrun, nil)

	rwid, err := ExecuteDeleteOperatingSystemByIDWorkflow(ctx, tc, siteIDs, osID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rwid == nil || *rwid != wid {
		t.Fatalf("expected workflow ID %q, got %v", wid, rwid)
	}
}

// Verifies the starter helper builds the deterministic workflow ID:
//
//	"operating-system-delete-by-id-<osID>-<sha1_hex(sorted siteIDs joined by '-')>"
//
// and that ordering of siteIDs in the input does NOT change the workflow ID.
func TestExecuteDeleteOperatingSystemByIDWorkflow_DeterministicWorkflowID(t *testing.T) {
	ctx := context.Background()
	a := uuid.New()
	b := uuid.New()
	osID := uuid.New()
	want := "operating-system-delete-by-id-" + osID.String() + "-" + expectedSiteHash([]uuid.UUID{a, b})

	for _, order := range [][]uuid.UUID{{a, b}, {b, a}} {
		wrun := &tmocks.WorkflowRun{}
		wrun.On("GetID").Return("ignored")

		tc := &tmocks.Client{}
		var capturedID string
		tc.Mock.On(
			"ExecuteWorkflow",
			ctx,
			mock.AnythingOfType("internal.StartWorkflowOptions"),
			mock.Anything, mock.Anything, mock.Anything,
		).Return(wrun, nil).Run(func(args mock.Arguments) {
			opts, ok := args.Get(1).(client.StartWorkflowOptions)
			if !ok {
				t.Fatalf("expected client.StartWorkflowOptions, got %T", args.Get(1))
			}
			capturedID = opts.ID
		})

		_, err := ExecuteDeleteOperatingSystemByIDWorkflow(ctx, tc, order, osID)
		if err != nil {
			t.Fatalf("order %v: unexpected error: %v", order, err)
		}
		if capturedID != want {
			t.Fatalf("order %v: workflow ID = %q, want %q", order, capturedID, want)
		}
	}
}
