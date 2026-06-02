#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

log_info() { printf '[INFO] %s\n' "$1"; }
log_warn() { printf '[WARN] %s\n' "$1"; }
log_error() { printf '[ERROR] %s\n' "$1"; }

if command -v ngc >/dev/null 2>&1; then
  log_info "NGC CLI already available, skipping installation."
  exit 0
fi

NGCCLI_VERSION="${NGCCLI_VERSION:-4.9.17}"
download_url="https://api.ngc.nvidia.com/v2/resources/nvidia/ngc-apps/ngc_cli/versions/${NGCCLI_VERSION}/files/ngccli_linux.zip"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

log_info "Downloading NGC CLI from $download_url"
curl -sSfL "$download_url" -o "$work_dir/ngccli.zip"
unzip -q "$work_dir/ngccli.zip" -d "$work_dir"

extract_dir=$(find "$work_dir" -maxdepth 2 -type d -name 'ngc-cli*' | head -n 1)
if [[ -z "$extract_dir" ]]; then
  log_error "Failed to locate extracted ngc-cli directory"
  exit 1
fi

install_root="$HOME/.local/ngc-cli"
rm -rf "$install_root"
mkdir -p "$install_root"
cp -R "$extract_dir"/. "$install_root/"

bin_path="$install_root/ngc"
if [[ ! -f "$bin_path" ]]; then
  log_error "Unable to find ngc executable after installation"
  exit 1
fi
chmod +x "$bin_path"

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$install_root" >> "$GITHUB_PATH"
else
  export PATH="$install_root:$PATH"
fi

log_info "NGC CLI installed at $install_root/ngc"

if [[ -d /usr/local/bin && -w /usr/local/bin ]]; then
  ln -sf "$bin_path" /usr/local/bin/ngc
  log_info "Symlinked ngc into /usr/local/bin"
else
  log_warn "Skipping symlink into /usr/local/bin (directory not writable); PATH updated via GITHUB_PATH."
fi

"$bin_path" --version
