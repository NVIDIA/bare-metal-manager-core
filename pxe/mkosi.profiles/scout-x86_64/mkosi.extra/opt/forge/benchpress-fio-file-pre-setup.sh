#!/usr/bin/env sh
 
cd /opt/benchpress && ./setup.sh || exit 1

cd /opt/benchpress && ./benchpress install fio_file || exit 1

nvidia-smi