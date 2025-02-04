#!/usr/bin/env sh

mkdir /tmp/test_fio_path

cd /opt/benchpress && ./setup.sh || exit 1

cd /opt/benchpress && ./benchpress install fio_file || exit 1
