// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package common

// Power control operation codes
const (
	OpCodePowerControlPowerOn       = "power_on"
	OpCodePowerControlForcePowerOn  = "force_power_on"
	OpCodePowerControlPowerOff      = "power_off"
	OpCodePowerControlForcePowerOff = "force_power_off"
	OpCodePowerControlRestart       = "restart"
	OpCodePowerControlForceRestart  = "force_restart"
	OpCodePowerControlWarmReset     = "warm_reset"
	OpCodePowerControlColdReset     = "cold_reset"
)

// Firmware control operation codes
const (
	OpCodeFirmwareControlUpgrade   = "upgrade"
	OpCodeFirmwareControlDowngrade = "downgrade"
	OpCodeFirmwareControlRollback  = "rollback"
)

// Bring-up operation codes
const (
	OpCodeBringUp = "bring_up"
	OpCodeIngest  = "ingest"
)
