#!/usr/bin/env sh
#
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

cmdline_file=${SCOUT_CMDLINE_FILE:-/proc/cmdline}
sys_class_net=${SCOUT_SYS_CLASS_NET:-/sys/class/net}
ip_command=${SCOUT_IP_COMMAND:-ip}

# A bare anynic kernel option is an escape hatch for debugging unsupported NICs.
cmdline=$(cat "$cmdline_file") || exit 1
case " $cmdline " in
	*" anynic "*)
		echo "Scout NIC filtering disabled: kernel_option=anynic"
		exit 0
		;;
esac

failed=false
for net_path in "$sys_class_net"/*
do
	[ -e "$net_path" ] || continue

	interface=${net_path##*/}
	if [ "$interface" = "lo" ]; then
		echo "Keeping network interface: interface=$interface reason=loopback"
		continue
	fi

	vendor=unknown
	# USB and virtual interfaces do not expose this PCI vendor file and must
	# therefore fall through to the disable path.
	if [ -r "$net_path/device/vendor" ]; then
		vendor=$(cat "$net_path/device/vendor")
	fi

	if [ "$vendor" = "0x15b3" ]; then
		echo "Keeping network interface: interface=$interface vendor=$vendor"
		continue
	fi

	echo "Disabling network interface: interface=$interface vendor=$vendor"
	if ! "$ip_command" link set dev "$interface" down; then
		echo "Failed to disable network interface: interface=$interface" >&2
		failed=true
	fi
done

[ "$failed" = false ]
