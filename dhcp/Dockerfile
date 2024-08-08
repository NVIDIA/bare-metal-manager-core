# SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
FROM carbide-runtime:latest

WORKDIR /app/code

RUN mkdir /var/run/kea/
RUN mkdir /var/lib/kea/

# This is copying the examples instead of the dev/ resource that the base image contains
# Should this be removed altogether?
COPY examples/kea-dhcp4-carbide.conf /etc/kea/kea-dhcp4-carbide.conf


EXPOSE 1079
EXPOSE 1089
