# Lenovo OneCLI

Lenovo XClarity Essentials OneCLI is a collection of several command-line applications, which can be used to configure
the server, collect service data for the server, update firmware and device drivers, and perform power-management
functions on the server.

Onecli can be downloaded from [https://support.lenovo.com/us/en/solutions/ht116433-lenovo-xclarity-essentials-onecli-onecli](https://support.lenovo.com/us/en/solutions/ht116433-lenovo-xclarity-essentials-onecli-onecli)

There are two common use-cases OneCLI is used for

- System board replacement which requires reprogramming system configuration settings
- Applying firmware updates

## System board replacement

Any time a system board is replaced the system metadata must be reprogrammed into the replacement system.
This includes setting the following:

- Serial number
- System type
- Platform identifier
- TPM policy
- TPM policy lock

To begin, set the following shell environment variables depending on the type of system being configured:

| | | |
|---|---|---|
|System Model|System Type|System Identifier|
|SR670 V2|7Z23CTOLWW|ThinkSystem SR670 V2|
|SR650 V2|7Z73CTOLWW|ThinkSystem SR650 V2 OVX|
|SR675 V3|7D9RCTOLWW|ThinkSystem SR675 V3 OVX|
|SR665 V3|7D9ACTOLWW|ThinkSystem SR665 V3 OVX|
|SR655 V3|7D9ECTOLWW|ThinkSystem SR655 V3 OVX|

As an example, for an SR670 V2 set the following:

```bash
export USER=root
export HOSTBMCIP=10.91.66.29
export HOSTBMCPW='<password>'
export SERVICETAG='<serial>'
export SYSTEMTYPE=7Z23CTOLWW
export SYSTEMIDENTFIER='ThinkSystem SR670 V2'
```

Then execute the following commands to set the values:

```bash
# Set System Serial Number
./onecli config set SYSTEM_PROD_DATA.SysInfoSerialNum $SERVICETAG --override --imm $USER:$HOSTBMCPW@$HOSTBMCIP

# Set Platform System Type
./onecli config set SYSTEM_PROD_DATA.SysInfoProdName $SYSTEMTYPE --override --imm $USER:$HOSTBMCPW@$HOSTBMCIP

# Set Platform identifier
./onecli config set SYSTEM_PROD_DATA.SysInfoProdIdentifier "$SYSTEMIDENTFIER" --override --imm $USER:$HOSTBMCPW@$HOSTBMCIP

# TPM Policy (if needed)
./onecli config show imm.TpmTcmPolicy --override --imm $USER:$HOSTBMCPW@$HOSTBMCIP
./onecli config set imm.TpmTcmPolicy "TpmOnly" --override --imm $USER:$HOSTBMCPW@$HOSTBMCIP

# TPM Policy lock (if needed)
./onecli config show imm.TpmTcmPolicyLock --override --imm $USER:$HOSTBMCPW@$HOSTBMCIP
./onecli config set imm.TpmTcmPolicyLock "Enabled" --override --imm $USER:$HOSTBMCPW@$HOSTBMCIP
```

There are other settings less commonly used that are also useful:

```bash
# Set UEFI BIOS password
./onecli config set IMM.UefiAdminPassword "$HOSTBMCPW" --imm $USER:$HOSTBMCPW@$HOSTBMCIP

# Reset XCC to factory defaults
./onecli config loaddefault --bmc $USER:$HOSTBMCPW@$HOSTBMCIP

# Enable IPMI over LAN
./onecli misc portctrl ipmikcs on --bmc $USER:$HOSTBMCPW@$HOSTBMCIP

# Reset NVRAM (requires enabling IPMI over LAN in XCC)
ipmitool -I lanplus -H $HOSTBMCIP -U $USER -P $HOSTBMCPW raw 0x3a 0x75 1 1
```

## Firmware Updates

Lenovo generally recommends applying firmware updates through the XCC interface, but OneCLI can be used as well.
Here is one example of how to flash multiple components at once (UEFI, XCC, LXPM) remotely. It can also be used
to flash all components, including GPUs, if run on the host itself, but that is not covered here.

```bash
~/onecli/onecli update scan --log 5 --bmc $USER:$HOSTBMCPW@$HOSTBMCIP
[1s]Certificate check finished [100%][=====================================================================>]
[6s]Scanning finished. [100%][=============================================================================>]

           Platform Information:
    ==================================
    | Machine Type | BMC Type |  OS  |
    ----------------------------------
    | 7Z23         | XCC      | None |
    ==================================

                              Scan Result:
    ===============================================================
    | No. |    Updatable Unit    |    Slot    | Installed Version |
    ---------------------------------------------------------------
    | 1   | BMC (Primary)        | N/A        | TGBT26F-1.60      |
    ---------------------------------------------------------------
    | 2   | BMC (Backup)         | N/A        | TGBT26F-1.60      |
    ---------------------------------------------------------------
    | 3   | UEFI                 | N/A        | U8E114E-1.10      |
    ---------------------------------------------------------------
    | 4   | LXPM                 | N/A        | *-* |
    ---------------------------------------------------------------
    | 5   | LXPM Windows Drivers | N/A        | *-* |
    ---------------------------------------------------------------
    | 6   | LXPM Linux Drivers   | N/A        | *-* |
    ---------------------------------------------------------------
    | 7   | POWER-PSU1           | PSU_Slot 1 | 7.52              |
    ---------------------------------------------------------------
    | 8   | POWER-PSU2           | PSU_Slot 2 | 7.52              |
    ---------------------------------------------------------------
    | 9   | POWER-PSU3           | PSU_Slot 3 | 7.52              |
    ---------------------------------------------------------------
    | 10  | POWER-PSU4           | PSU_Slot 4 | 7.52              |
    ===============================================================
Scan results saved to: /home/apatten/tmp/lenovo/logs/OneCli-20250626-162657-2786767/Onecli-update-scan.xml
Succeed.

~/onecli/onecli update acquire --mt 7Z23 --scope latest --type fw --ostype none --dir 7Z23 --output ./logs
# <downloads a bunch of stuff - You wil want to winnow it down to the basics, UEFI, XCC and LXPM #

~/onecli/onecli update compare --scope latest --dir 7Z23/ --output ./logs --bmc $USER:$HOSTBMCPW@$HOSTBMCIP
[1s]Certificate check finished [100%][=====================================================================>]
[4s]Scanning finished. [100%][=============================================================================>]

           Platform Information:
    ==================================
    | Machine Type | BMC Type |  OS  |
    ----------------------------------
    | 7Z23         | XCC      | None |
    ==================================

                              Scan Result:
    ===============================================================
    | No. |    Updatable Unit    |    Slot    | Installed Version |
    ---------------------------------------------------------------
    | 1   | BMC (Primary)        | N/A        | TGBT26F-1.60      |
    ---------------------------------------------------------------
    | 2   | BMC (Backup)         | N/A        | TGBT26F-1.60      |
    ---------------------------------------------------------------
    | 3   | UEFI                 | N/A        | U8E114E-1.10      |
    ---------------------------------------------------------------
    | 4   | LXPM                 | N/A        | *-* |
    ---------------------------------------------------------------
    | 5   | LXPM Windows Drivers | N/A        | *-* |
    ---------------------------------------------------------------
    | 6   | LXPM Linux Drivers   | N/A        | *-* |
    ---------------------------------------------------------------
    | 7   | POWER-PSU1           | PSU_Slot 1 | 7.52              |
    ---------------------------------------------------------------
    | 8   | POWER-PSU2           | PSU_Slot 2 | 7.52              |
    ---------------------------------------------------------------
    | 9   | POWER-PSU3           | PSU_Slot 3 | 7.52              |
    ---------------------------------------------------------------
    | 10  | POWER-PSU4           | PSU_Slot 4 | 7.52              |
    ===============================================================
Scan results saved to: /home/apatten/tmp/lenovo/./logs/Onecli-update-scan.xml
Querying updates done, the result is stored to /home/apatten/tmp/lenovo/./logs/Onecli-update-query.xml

                                                          Comparing Updates:
    =============================================================================================================================
    | No. | Updatable Unit | Slot |   New Version   | Installed Version | Selected |                 Update ID                  |
    -----------------------------------------------------------------------------------------------------------------------------
    | 1   | UEFI           | N/A  | U8E112A-1.02    | U8E114E-1.10      | No (*20) | lnvgy_fw_uefi_u8e112a-1.02_anyos_32-64     |
    -----------------------------------------------------------------------------------------------------------------------------
    | 2   | UEFI           | N/A  | u8e132e-3.20    | U8E114E-1.10      | No (*9)  | lnvgy_fw_uefi_u8e132e-3.20_anyos_32-64     |
    -----------------------------------------------------------------------------------------------------------------------------
    | 3   | LXPM           | N/A  | xwl128g-3.31.00 | *-* | YES      | lnvgy_fw_lxpm_xwl128g-3.31.00_anyos_noarch |
    -----------------------------------------------------------------------------------------------------------------------------
    | 4   | BMC (Primary)  | N/A  | tgbt56d-5.10    | TGBT26F-1.60      | YES      | lnvgy_fw_xcc_tgbt56d-5.10_anyos_noarch     |
    -----------------------------------------------------------------------------------------------------------------------------
    | 5   | UEFI           | N/A  | u8e122h-1.50    | U8E114E-1.10      | YES      | lnvgy_fw_uefi_u8e122h-1.50_anyos_32-64     |
    =============================================================================================================================
    *20-This is prerequisite of another package and the installed version is met the requirement
    *9-The requisite packages do not exist

Compare updates done, the result is stored to /home/apatten/tmp/lenovo/./logs/Onecli-update-compare.xml
Succeed.

~/onecli/onecli update flash --comparexml /home/apatten/tmp/lenovo/./logs/Onecli-update-compare.xml --dir 7Z23/ \
--output ./logs --bmc $USER:$HOSTBMCPW@$HOSTBMCIP
[1s]Certificate check finished [100%][=====================================================================>]

Start OOB flashing...

Current flashing ID:lnvgy_fw_lxpm_xwl128g-3.31.00_anyos_noarch

[2s]Uploading succeed [100%][==============================================================================>]

[20s]Task Completed [100%][================================================================================>]

Current flashing ID:lnvgy_fw_xcc_tgbt56d-5.10_anyos_noarch

[52s]Uploading succeed [100%][=============================================================================>]

[1m6s]Task Completed [100%][===============================================================================>]
[4m53s]Succeed to Reboot BMC. [100%][======================================================================>]

Current flashing ID:lnvgy_fw_uefi_u8e122h-1.50_anyos_32-64

[8s]Uploading succeed [100%][==============================================================================>]

[3m7s]Task Completed [100%][===============================================================================>]

                                                   Flash Results:
    ===========================================================================================================
    | No. | Updatable Unit | Slot | Activation Status  | Result  |                 Update ID                  |
    -----------------------------------------------------------------------------------------------------------
    | 1   | LXPM           | N/A  | Activated          | success | lnvgy_fw_lxpm_xwl128g-3.31.00_anyos_noarch |
    -----------------------------------------------------------------------------------------------------------
    | 2   | BMC (Primary)  | N/A  | Activated          | success | lnvgy_fw_xcc_tgbt56d-5.10_anyos_noarch     |
    -----------------------------------------------------------------------------------------------------------
    | 3   | UEFI           | N/A  | Pending restart OS | success | lnvgy_fw_uefi_u8e122h-1.50_anyos_32-64     |
    ===========================================================================================================
Package statistic results:
3 package(s) attempted
3 package(s) succeeded

Updatable Unit statistic results:
3 update(s) attempted
3 update(s) succeeded

Succeeded in running flash command
```

Updates to a single component can be done as well.

```bash
./onecli update flash --scope individual --includeid lnvgy_fw_uefi_u8e128n-2.60_anyos_32-64 --dir 7Z23 --output ./logs --bmc $USER:$HOSTBMCPW@$HOSTBMCIP
```
