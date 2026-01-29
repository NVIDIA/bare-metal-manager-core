#!/bin/bash

#PACKAGES="cuda-12-9 chrpath libnvidia-nscq-575=575.57.08-1 libnccl2=2.27.3-1+cuda12.9 libnccl-dev=2.27.3-1+cuda12.9 automake autoconf autotools-dev bison debhelper ethtool flex gfortran git graphviz iperf jq libfuse2t64 libgfortran5 libltdl-dev libnl-3-dev libnl-route-3-dev libnuma1 libopenmpi-dev libusb-1.0-0 lsb-base lsof m4 openmpi-bin python3-pip python3-numpy quilt tcl tk  pkg-config  libusb-1.0-0"
PACKAGES="cuda-13-1 chrpath libnvidia-nscq-580=580.126.09-1 libnccl2=2.29.2-1+cuda13.1 libnccl-dev=2.29.2-1+cuda13.1 automake autoconf autotools-dev bison debhelper ethtool flex gfortran git graphviz iperf jq libfuse2t64 libgfortran5 libltdl-dev libnl-3-dev libnl-route-3-dev libnuma1 libopenmpi-dev libusb-1.0-0 lsb-base lsof m4 openmpi-bin python3-pip python3-numpy quilt tcl tk  pkg-config  libusb-1.0-0"

export DEBIAN_FRONTEND=noninteractive
apt-get -y install ${PACKAGES}

chmod +x /opt/forge/startShorelineAgent.sh
chmod +x /opt/forge/stopShorelineAgent.sh
sed -i 's/^\s*AuthorizedKeysFile/#&/' /etc/ssh/sshd_config
sed -i -E 's/^#?\s*PermitRootLogin\s+.*/PermitRootLogin yes/' /etc/ssh/sshd_config
systemctl enable shoreline.service


export OFED_VERSION="24.10-0.7.0.0"
export OS_VERSION="24.04"
export KERNEL_VERSION="6.11.0-1012-nvidia-64k"


cp /opt/forge/dkms /usr/sbin/dkms
wget https://www.mellanox.com/downloads/DOCA/DOCA_v3.0.0/host/doca-host_3.0.0-058000-25.04-ubuntu2404_arm64.deb
dpkg -i doca-host_3.0.0-058000-25.04-ubuntu2404_arm64.deb
apt remove mft
dpkg -i   extract/usr/share/doca-host-3.1.0-091000-25.07-ubuntu2404/repo/pool/mft_4.33.0-169_arm64.deb   extract/usr/share/doca-host-3.1.0-091000-25.07-ubuntu2404/repo/pool/kernel-mft-dkms_4.33.0.169-1_all.deb

dpkg -i doca-host_3.0.0-058000-25.04-ubuntu2404_arm64.deb
apt-get update

apt install -y doca-extra
/opt/mellanox/doca/tools/doca-kernel-support > ~/doca-kernel-support-output.txt 2>&1
INSTALL_CMD=$(cat ~/doca-kernel-support-output.txt | grep 'dpkg --install')
bash -c "$INSTALL_CMD"
apt update
apt install -y doca-ofed
apt install -y doca-ofed-userspace doca-kernel-6.11.0.1012.nvidia.64k
apt install -y doca-all


# export URL=http://content.mellanox.com/ofed/MLNX_OFED-${OFED_VERSION}/MLNX_OFED_LINUX-${OFED_VERSION}-ubuntu${OS_VERSION}-aarch64.tgz
# wget ${URL} -O /tmp/mlnx_ofed.tgz
# tar -xvzf /tmp/mlnx_ofed.tgz  -C /tmp
# /tmp/MLNX_OFED_LINUX-${OFED_VERSION}-ubuntu${OS_VERSION}-aarch64/mlnxofedinstall --force --all --skip-unsupported-devices-check --add-kernel-support --kernel ${KERNEL_VERSION}  --kernel-sources /usr/src/linux-headers-${KERNEL_VERSION}
# rm -rf /tmp/mlnx_ofed.tgz /tmp/MLNX_OFED_LINUX-${OFED_VERSION}-ubuntu${OS_VERSION}-aarch64


export HPCX_VERSION="2.25"

curl -o /tmp/hpcx-v${HPCX_VERSION}-gcc-mlnx_ofed-ubuntu${OS_VERSION}-cuda13-aarch64.tbz 'https://urm.nvidia.com/artifactory/sw-ngc-forge-cargo-local/misc/hpcx-v2.25-gcc-doca_ofed-ubuntu24.04-cuda13-aarch64.tbz'
#curl -o /tmp/hpcx-v${HPCX_VERSION}-gcc-mlnx_ofed-ubuntu${OS_VERSION}-cuda12-aarch64.tbz 'http://hpcweb.lab.mtl.com/hpc/noarch/HPCX/release/v'${HPCX_VERSION}'/RC5/CUDA12/hpcx-v'${HPCX_VERSION}'-gcc-doca_ofed-ubuntu'${OS_VERSION}'-cuda12-aarch64.tbz'

#curl -o /tmp/hpcx-v${HPCX_VERSION}-gcc-mlnx_ofed-ubuntu${OS_VERSION}-cuda12-aarch64.tbz 'https://content.mellanox.com/hpc/hpc-x/v'${HPCX_VERSION}'/hpcx-v'${HPCX_VERSION}'-gcc-doca_ofed-ubuntu24.04-cuda12-aarch64.tbz'

tar -xvf /tmp/hpcx-v${HPCX_VERSION}-gcc-mlnx_ofed-ubuntu${OS_VERSION}-cuda13-aarch64.tbz -C /usr/local/bin
rm /tmp/hpcx-v${HPCX_VERSION}-gcc-mlnx_ofed-ubuntu${OS_VERSION}-cuda13-aarch64.tbz

mkdir -p /opt/nccl-tests && chmod 777 /opt/nccl-tests  && cd /opt/nccl-tests
git clone https://github.com/NVIDIA/nccl-tests.git .

mkdir -p /opt/nvbandwidth && chmod 777 /opt/nvbandwidth && cd /opt/nvbandwidth
git clone https://github.com/NVIDIA/nvbandwidth.git .
sed -i '1i set(CMAKE_CUDA_ARCHITECTURES 100)' CMakeLists.txt
sed -i '1i set(MULTINODE  1)' CMakeLists.txt

./debian_install.sh
cp nvbandwidth /usr/local/bin

systemctl stop forge-scout 
systemctl disable forge-scout 

cat > /etc/environment << 'EOF'
CUDA_HOME=/usr/local/cuda-13.1
LD_LIBRARY_PATH=/usr/mpi/gcc/openmpi-4.1.7rc1/lib:/usr/local/cuda-13.1/lib64:/usr/local/cuda-13.1/lib64
PATH=/usr/mpi/gcc/openmpi-4.1.7rc1/bin:/usr/local/cuda-13.1/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EOF