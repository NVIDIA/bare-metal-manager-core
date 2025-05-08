#!/usr/bin/env sh

cd /opt/benchpress && ./setup.sh || exit 1

cd /opt/benchpress && ./benchpress install mm_mem_peak_bandwidth || exit 1
