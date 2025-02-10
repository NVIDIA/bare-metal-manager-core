#!/usr/bin/env sh

cd /opt/benchpress && ./setup.sh || exit 1

cd /opt/benchpress && ./benchpress install cpu_2017_fp_rate_light || exit 1
