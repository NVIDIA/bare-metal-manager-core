#!/usr/bin/env sh

wget https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/cuda-keyring_1.0-1_all.deb
dpkg -i cuda-keyring_1.0-1_all.deb
apt-get update
apt-get install -y cuda 
 
cd /opt/benchpress && ./setup.sh || exit 1

cd /opt/benchpress && ./benchpress install cuda_samples || exit 1

# cd /opt/benchpress && ./benchpress run cuda_samples || exit 1
nvidia-smi