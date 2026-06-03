// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	cutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
)

func TestNewAPIUserFromDBUser(t *testing.T) {
	type args struct {
		dbUser cdbm.User
	}

	u := &cdbm.User{
		ID:          uuid.New(),
		StarfleetID: cutil.GetPtr("test123"),
		FirstName:   cutil.GetPtr("John"),
		LastName:    cutil.GetPtr("Doe"),
		Email:       cutil.GetPtr("jdoe@test.com"),
		Created:     time.Now(),
		Updated:     time.Now(),
	}

	tests := []struct {
		name string
		args args
		want *APIUser
	}{
		{
			name: "test initializing APi model for User",
			args: args{
				dbUser: *u,
			},
			want: &APIUser{
				ID:        u.ID.String(),
				FirstName: u.FirstName,
				LastName:  u.LastName,
				Email:     u.Email,
				Created:   u.Created,
				Updated:   u.Updated,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewAPIUserFromDBUser(tt.args.dbUser); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAPIUserFromDBUser() = %v, want %v", got, tt.want)
			}
		})
	}
}
