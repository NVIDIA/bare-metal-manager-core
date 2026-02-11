#!/bin/bash
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

MIN_UPTIME=86400
ROOTFS_INFO_FILE="/rootfs_info.txt"

# If we've not reached the minimum uptime, exit straight away
uptime=$(awk -F. '{print $1}' < /proc/uptime)
if (( $uptime < $MIN_UPTIME ))
then
	echo "Min uptime not reached ($uptime < $MIN_UPTIME)"
	exit 0
fi

# Get the last updated value for the main scout image
arch=$(uname -m)
scout_url="http://carbide-static-pxe.forge/public/blobs/internal/${arch}/scout.cpio.zst"
www_last_modified_str=$(curl -sf --head ${scout_url} 2>/dev/null | sed 's/\r//g' | grep Last-Modified)
if (( $? != 0 ))
then
	echo "Unable to query last-modified value for ${scout_url}"
	exit 1
fi

# Get the last updated value from when we booted
# This should have been stored by the scout-loader script
my_last_modified_str=$(grep Last-Modified ${ROOTFS_INFO_FILE})
if (( $? != 0 ))
then
	echo "Unable to query last-modified value from when we booted"
	echo "Scout loader should have put that in ${ROOTFS_INFO_FILE}"
	exit 1
fi

if [ "${www_last_modified_str}" != "${my_last_modified_str}" ]
then
	echo "Newer scout available, rebooting"
	reboot
fi
