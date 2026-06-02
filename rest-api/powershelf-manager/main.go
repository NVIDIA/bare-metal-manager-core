// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/NVIDIA/infra-controller-rest/powershelf-manager/cmd"
	"github.com/NVIDIA/infra-controller-rest/powershelf-manager/pkg/common/log"
)

func main() {
	log.Init()
	cmd.Execute()
}
