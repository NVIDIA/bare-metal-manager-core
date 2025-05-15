<div class="mermaid-zoom" style="width: 60vw; height: 80vh;">
<!-- Keep the empty line after this or here or the diagram will break -->

```mermaid
  %%{init: { 'sequence': {'useMaxWidth':false} } }%%

  stateDiagram-v2
  %%classDef Ready fill:green,color:white,font-weight:bold,font-size:30px,stroke-width:2px,stroke:yellow
  %%classDef Assigned fill:#FFFDD0,font-weight:bold,font-size:23px,stroke-width:2px,stroke:green
  %%classDef reprov fill:#F9E6BD,font-weight:bold,font-size:23px,stroke-width:2px,stroke:black
  %%classDef HostInit fill:#CAE2F9,font-weight:bold,font-size:23px,stroke-width:2px,stroke:black
  %%classDef DpuInit fill:#C7F3ED,font-weight:bold,font-size:23px,stroke-width:2px,stroke:black
  %%classDef cleanup fill:white,font-weight:bold,font-size:23px,stroke-width:2px,stroke:orange
  %%classDef failed fill:#f00,color:white,font-size:25px,font-weight:bold,stroke-width:2px,stroke:yellow


  [*] --> DpuDiscoveringState: Site Explorer has created managed host with predicted host.

  state DpuDiscoveringState {
    [*] --> DD_EnableRshim
    DD_EnableRshim --> DD_DisableSecureBoot: Rshim is enabled
  }

  DD_DisableSecureBoot --> DpuInit: Secure Boot is disabled
  state DpuInit {
    [*] --> DPU_Init
    DPU_Init --> DPU_WaitingForPlatformPowercycle_OFF: Discovered
    DPU_WaitingForPlatformPowercycle_OFF --> DPU_WaitingForPlatformPowercycle_ON: Power off the host
    DPU_WaitingForPlatformPowercycle_ON --> DPU_WaitingForPlatformConfiguration: Power On the host
    DPU_WaitingForPlatformConfiguration --> DPU_WaitingForNetworkConfig: Call forge-setup/uefi-setup and restart DPU
  }
  DPU_WaitingForNetworkConfig --> HostInit: DPU acknowledged newest network configuration is fetched \nand applied and aggregate health status is good
  state HostInit {
    [*] --> Host_EnableIpmiOverLan 
    Host_EnableIpmiOverLan --> Host_WaitingForPlatformConfiguration: Enable IPMI over LAN access
    Host_WaitingForPlatformConfiguration --> Host_SetBootOrder: Call forge setup/Restart Host
    state attestation_enabled <<choice>>
    Host_SetBootOrder --> attestation_enabled: set primary interface MAC as bootable interface\nRestart host
    attestation_enabled --> Host_Measuring: if attestation is enabled
    attestation_enabled --> Host_WaitingForDiscovery: if attestation is disabled
    
    Host_Measuring --> Host_WaitingForDiscovery: Measurement status passed
    Host_WaitingForDiscovery --> Host_UefiSetup: Discovery is Successful.
    state Host_UefiSetup {
      [*] --> UnlockHost
      UnlockHost --> SetUefiPassword: Lockdown status is disabled
      SetUefiPassword --> Host_WaitForPasswordJobScheduled: Password is set using redfish
      Host_WaitForPasswordJobScheduled --> Uefisetup_PowercycleHost: Wait until password job is scheduled.
      Uefisetup_PowercycleHost --> Uefisetup_WaitForPasswordJobCompletion: Restart the host.\nRestart will do power cycle when it applies the password job.
      Uefisetup_WaitForPasswordJobCompletion --> Uefisetup_LockdownHost: Password job is successful.
    }
    Uefisetup_LockdownHost --> WaitingForLockdown
    state WaitingForLockdown {
      [*] --> TimeWaitForDPUDown: Waiting so that DPU goes down
      TimeWaitForDPUDown --> WaitForDPUUp: Wait time over
    }
  }
  WaitingForLockdown --> BomValidating: Lockdown is successful
  state validation_enabled <<choice>>
  BomValidating --> validation_enabled: Bom Validation is successful
  validation_enabled --> Validation: if True
  validation_enabled --> Discovered: if False
  state Validation {
    [*] --> V_RebootHost
    V_RebootHost --> V_MachineValidating
  }
  Validation --> Discovered: Machine validation tests are passed
  Discovered --> Ready: On Reboot
  state Ready <<choice>>
  state FirmwareUpgradeNeeded <<choice>>
  Ready --> FirmwareUpgradeNeeded: if DPU reprovision is requested
  Ready --> Assigned: if Instance Creation is requested
  Ready --> Validation: if On-Demand Machine validation is requested
  Ready --> HostReprovision: If Host FW updates should be installed

  state Assigned {
    [*] --> A_WaitingForNetworkSegmentToBeReady
    A_WaitingForNetworkSegmentToBeReady --> A_WaitingForNetworkConfig: Network segment created for vpc_prefixes are ready
    A_WaitingForNetworkConfig --> A_WaitingForStorageConfig: DPU Agent responded with network ready status
    A_WaitingForStorageConfig --> A_WaitingForRebootToReady: Storage is ready, reboot now.
    A_WaitingForRebootToReady --> A_Ready: Tenant Network Ready
    A_Ready --> A_BootingWithDiscoveryImage: Instance delete request received, or reprovision requested
    A_BootingWithDiscoveryImage --> A_SwitchToAdminNetwork: Host rebooted with discovery image
    A_SwitchToAdminNetwork --> A_WaitingForNetworkReconfig: Configured to move to Admin Network
    A_BootingWithDiscoveryImage --> A_DPUReprovision: DPU reprovisioning in progress.  Roughly follows DPUReprovision.
    A_DPUReprovision --> A_Ready: Various DPU reprovision states end in state ReprovisionState#58;#58;RebootHost which then goes to A_Ready
    A_BootingWithDiscoveryImage --> A_HostReprovision: Host firmware updates in progress.  Roughly follows HostReprovision.
    A_HostReprovision --> A_Ready: Completion of host firmware updates
    A_Ready --> NetworkUpdate: On NetworkUpdate Request

    state NetworkUpdate {
      [*] --> NW_WaitingForNetworkSegmentToBeReady: 
      NW_WaitingForNetworkSegmentToBeReady --> NW_WaitingForConfigSynced: Network segment created for vpc_prefixes are ready.
      NW_WaitingForConfigSynced --> NW_ReleaseOldResources: DPU Agent responded with network ready with latest config
    }
    NetworkUpdate --> A_Ready: Released old resources like IP/segments/loopback IP
  }
  A_WaitingForNetworkReconfig --> WaitingForCleanup: Instance is deleted from Db

  state WaitingForCleanup {
    [*] --> HostCleanup : Host performing cleanup
  }
  HostCleanup --> Validation: Host cleanup finished
  FirmwareUpgradeNeeded --> DPUReprovision: if firmware upgrade is needed
  FirmwareUpgradeNeeded --> Reprov_WaitingForNetworkInstall: if firmware upgrade is NOT needed
  state DPUReprovision {
    [*] --> Reprov_FirmwareUpgrade
    Reprov_FirmwareUpgrade --> Reprov_WaitingForNetworkInstall: DPU rebooted after firmware upgrade
    Reprov_WaitingForNetworkInstall --> Reprov_BufferTime: DPU rebooted and discovery is succesful.
    Reprov_BufferTime --> Reprov_WaitingForNetworkConfig: Wait time over
  }

  Reprov_WaitingForNetworkConfig --> Host_Discovered: DPU acknowledged newest network configuration is fetched \nand applied and aggregate health status is good

  %% Anystate can move to Failed State based on failure cause.
  DPUInit       --> Failed         : On Failure
  HostInit      --> Failed         : On Failure
  Ready             --> Failed         : On Failure
  Assigned          --> Failed         : On Failure
  WaitingForCleanup --> Failed         : On Failure

  state HostReprovision {
    [*] --> HostReprovision_CheckingFirmware
    HostReprovision_CheckingFirmware --> HostReprovision_WaitingForFirmwareUpgrade

   %%
    HostReprovision_WaitingForFirmwareUpgrade --> HostReprovision_ResetForNewFirmware
    HostReprovision_ResetForNewFirmware --> HostReprovision_NewFirmwareReportedWait
    HostReprovision_NewFirmwareReportedWait --> HostReprovision_FailedFirmwareUpgrade
    HostReprovision_NewFirmwareReportedWait --> HostReprovision_CheckingFirmware
    HostReprovision_FailedFirmwareUpgrade
  }
  HostReprovision_CheckingFirmware --> WaitingForLockdown
  HostReprovision_CheckingFirmware --> Ready
```

</div>