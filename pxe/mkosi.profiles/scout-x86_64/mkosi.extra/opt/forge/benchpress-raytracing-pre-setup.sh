#!/usr/bin/env sh
 
cd /opt/benchpress && ./setup.sh || exit 1

cd /opt/benchpress && ./benchpress install raytracing_vk || exit 1

nvidia-smi