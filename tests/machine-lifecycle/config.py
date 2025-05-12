# Ingestion wait times
WAIT_FOR_HOSTINIT = 60 * 120
WAIT_FOR_READY = 60 * 150
WAIT_FOR_INSTANCE = 60 * 45
WAIT_FOR_HOSTINIT_AFTER_DOWNGRADE = 60 * 150

# Minimum supported DPU firmware versions and where to download them from (DOCA 2.5.0)
BFB_VERSION = "2.5.0"
NIC_VERSION = "32.39.2048"
BMC_VERSION = "23.10"
CEC_VERSION = "00.02.0152.0000"

# Note: only DOCA 2.7.0 and higher include the BMC, CEC, and NIC in the BFB
BFB_URL = "https://urm.nvidia.com/artifactory/sw-mlnx-bluefield-generic/Ubuntu22.04/DOCA_2.5.0_BSP_4.5.0_Ubuntu_22.04-1.23-10.prod.bfb"
NIC_FW_URL = "https://www.mellanox.com/downloads/firmware/fw-BlueField-3-rel-32_39_2048-900-9D3B6-00CV-A_Ax-NVME-20.4.1-UEFI-21.4.13-UEFI-22.4.12-UEFI-14.32.17-FlexBoot-3.7.300.signed.bin.zip"
BMC_FW_URL = "https://urm.nvidia.com/artifactory/sw-bmc-generic-local/BF3/BF3BMC-23.10-5/OPN/bf3-bmc-23.10-5_opn.fwpkg"
CEC_FW_URL = "https://urm.nvidia.com/artifactory/sw-bmc-generic-local/Glacier/00.02.0152.0000/sign/n02/rel-prod/cec1736-ecfw-00.02.0152.0000-n02-rel-prod.fwpkg"

# Expected versions to which Forge should auto-upgrade (currently DOCA 2.9.2 / HBN 2.4.2)
BFB_VERSION_UP = "2.9.2"
NIC_VERSION_UP = "32.43.2566"
BMC_VERSION_UP = "24.10"
CEC_VERSION_UP = "00.02.0195.0000"
