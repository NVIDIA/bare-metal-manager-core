#!/usr/bin/env bash
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

set -euo pipefail

# Function to display usage
usage() {
    cat << EOF
Usage: $0 <ip_range>

Creates a MetalLB IP pool and a single reverse proxy service for machine-a-tron BMC mock.
Uses \$server_addr to dynamically set Forwarded: host=<external-ip> header.

Arguments:
    ip_range    IP range in format: 192.168.2.2-192.168.2.6

Example:
    $0 192.168.2.2-192.168.2.6
EOF
    exit 1
}

# Function to generate individual LoadBalancer services
generate_loadbalancer_services() {
    local ip_range="$1"
    local start_ip=$(echo "$ip_range" | cut -d'-' -f1)
    local end_ip=$(echo "$ip_range" | cut -d'-' -f2)

    # Convert IPs to integers for comparison
    local start_int=$(ip_to_int "$start_ip")
    local end_int=$(ip_to_int "$end_ip")

    # Generate LoadBalancer service for each IP
    for ((i=start_int; i<=end_int; i++)); do
        local current_ip=$(int_to_ip $i)
        local service_name="machine-a-tron-bmc-mock-$(echo "$current_ip" | tr '.' '-')"

        cat << EOF
---
apiVersion: v1
kind: Service
metadata:
  name: $service_name
  namespace: forge-system
  annotations:
    metallb.universe.tf/loadBalancerIPs: $current_ip
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local
  internalTrafficPolicy: Cluster
  selector:
    app: machine-a-tron-proxy
  ports:
    - name: https
      port: 443
      targetPort: 443
      protocol: TCP
EOF
    done
}

# Function to convert IP to integer
ip_to_int() {
    local ip="$1"
    IFS='.' read -ra OCTETS <<< "$ip"
    echo $(( (${OCTETS[0]} << 24) + (${OCTETS[1]} << 16) + (${OCTETS[2]} << 8) + ${OCTETS[3]} ))
}

# Function to convert integer to IP
int_to_ip() {
    local int="$1"
    echo $(( (int >> 24) & 255 )).$(( (int >> 16) & 255 )).$(( (int >> 8) & 255 )).$(( int & 255 ))
}

# Main script logic
main() {
    # Check if IP range is provided
    if [[ $# -ne 1 ]]; then
        usage
    fi

    local ip_range="$1"

    # Generate MetalLB IP pool
    cat << EOF
---
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: machine-a-tron-bmc-mock-pool-$ip_range
  namespace: metallb-system
spec:
  addresses:
    - $ip_range
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-config-machine-a-tron-proxy
  namespace: forge-system
data:
  nginx.conf: |
    events {
      worker_connections 1024;
    }
    http {
      upstream machine_a_tron_backend {
        server machine-a-tron-bmc-mock.forge-system:1266;
      }
      server {
        listen 443 ssl;
        ssl_certificate /etc/ssl/certs/tls.crt;
        ssl_certificate_key /etc/ssl/private/tls.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
          proxy_pass https://machine_a_tron_backend;
          proxy_set_header Host \$host;
          proxy_set_header X-Real-IP \$remote_addr;
          proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto \$scheme;
          proxy_set_header Forwarded "host=\$http_host";
          proxy_ssl_verify off;
        }
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: machine-a-tron-proxy
  namespace: forge-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: machine-a-tron-proxy
  template:
    metadata:
      labels:
        app: machine-a-tron-proxy
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 443
        volumeMounts:
        - name: nginx-config
          mountPath: /etc/nginx/nginx.conf
          subPath: nginx.conf
        - name: ssl-cert
          mountPath: /etc/ssl/certs
          readOnly: true
        - name: ssl-key
          mountPath: /etc/ssl/private
          readOnly: true
      volumes:
      - name: nginx-config
        configMap:
          name: nginx-config-machine-a-tron-proxy
      - name: ssl-cert
        secret:
          secretName: machine-a-tron-certificate
          items:
          - key: tls.crt
            path: tls.crt
      - name: ssl-key
        secret:
          secretName: machine-a-tron-certificate
          items:
          - key: tls.key
            path: tls.key
EOF

    # Generate individual LoadBalancer services
    generate_loadbalancer_services "$ip_range"
}

# Run main function with all arguments
main "$@"
