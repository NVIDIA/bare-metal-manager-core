#!/usr/bin/env sh
 
cd /opt/benchpress && ./setup.sh || exit 1

apt-get update
apt-get install -y gdm3 autoconf libtool
cd /opt/benchpress && ./benchpress install raytracing_vk || exit 1

nvidia-smi