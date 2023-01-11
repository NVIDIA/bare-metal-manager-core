use crate::common::*;
use std::fmt;
use std::fmt::Formatter;

serde_with::with_prefix!(prefix_current_nic "CurrentNIC.1.");
serde_with::with_prefix!(prefix_nic "NIC.1.");
serde_with::with_prefix!(prefix_current_ipv6 "CurrentIPv6.1.");
serde_with::with_prefix!(prefix_current_ipv4 "CurrentIPv4.1.");
serde_with::with_prefix!(prefix_ipv6 "IPv6.1.");
serde_with::with_prefix!(prefix_ipv4 "IPv4.1.");
serde_with::with_prefix!(prefix_info "Info.1.");
serde_with::with_prefix!(prefix_ipmi_lan "IPMILan.1.");
serde_with::with_prefix!(prefix_ipmi_sol "IPMISOL.1.");
serde_with::with_prefix!(prefix_local_security "LocalSecurity.1.");
serde_with::with_prefix!(prefix_logging "Logging.1.");
serde_with::with_prefix!(prefix_os_bmc "OS-BMC.1.");
serde_with::with_prefix!(prefix_platform_capability "PlatformCapability.1.");
serde_with::with_prefix!(prefix_racadm "Racadm.1.");
serde_with::with_prefix!(prefix_redfish_eventing "RedfishEventing.1.");
serde_with::with_prefix!(prefix_rfs "RFS.1.");
serde_with::with_prefix!(prefix_ssh "SSH.1.");
serde_with::with_prefix!(prefix_security "Security.1.");
serde_with::with_prefix!(prefix_security_certificate1 "SecurityCertificate.1.");
serde_with::with_prefix!(prefix_security_certificate2 "SecurityCertificate.2.");
serde_with::with_prefix!(prefix_serial "Serial.1.");
serde_with::with_prefix!(prefix_serial_redirection "SerialRedirection.1.");
serde_with::with_prefix!(prefix_service_module "ServiceModule.1.");
serde_with::with_prefix!(prefix_server_boot "ServerBoot.1.");
serde_with::with_prefix!(prefix_support_assist "SupportAssist.1.");
serde_with::with_prefix!(prefix_sys_info "SysInfo.1.");
serde_with::with_prefix!(prefix_sys_log "SysLog.1.");
serde_with::with_prefix!(prefix_time "Time.1.");
serde_with::with_prefix!(prefix_virtual_console "VirtualConsole.1.");
serde_with::with_prefix!(prefix_virtual_media "VirtualMedia.1.");
serde_with::with_prefix!(prefix_vnc_server "VNCServer.1.");
serde_with::with_prefix!(prefix_web_server "WebServer.1.");
serde_with::with_prefix!(prefix_update "Update.1.");

serde_with::with_prefix!(prefix_users1 "Users.1.");
serde_with::with_prefix!(prefix_users2 "Users.2.");
serde_with::with_prefix!(prefix_users3 "Users.3.");
serde_with::with_prefix!(prefix_users4 "Users.4.");
serde_with::with_prefix!(prefix_users5 "Users.5.");
serde_with::with_prefix!(prefix_users6 "Users.6.");
serde_with::with_prefix!(prefix_users7 "Users.7.");
serde_with::with_prefix!(prefix_users8 "Users.8.");
serde_with::with_prefix!(prefix_users9 "Users.9.");
serde_with::with_prefix!(prefix_users10 "Users.10.");
serde_with::with_prefix!(prefix_users11 "Users.11.");
serde_with::with_prefix!(prefix_users12 "Users.12.");
serde_with::with_prefix!(prefix_users13 "Users.13.");
serde_with::with_prefix!(prefix_users14 "Users.14.");
serde_with::with_prefix!(prefix_users15 "Users.15.");
serde_with::with_prefix!(prefix_users16 "Users.16.");

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellSupportAssist {
    pub default_protocol_port: i64,
    #[serde(rename = "HostOSProxyAddress")]
    pub host_os_proxy_address: String,
    #[serde(rename = "HostOSProxyUserName")]
    pub host_os_proxy_user_name: String,
    #[serde(rename = "HostOSProxyPassword")]
    pub host_os_proxy_password: Option<String>,
    #[serde(rename = "HostOSProxyPort")]
    pub host_os_proxy_port: i64,
    pub default_protocol: String,
    pub email_opt_in: String,
    pub event_based_auto_collection: String,
    pub filter_auto_collections: String,
    #[serde(rename = "HostOSProxyConfigured")]
    pub host_os_proxy_configured: String,
    #[serde(rename = "NativeOSLogsCollectionSupported")]
    pub native_os_logs_collection_supported: String,
    pub preferred_language: String,
    pub pro_support_plus_recommendations_report: String,
    pub request_technician_for_parts_dispatch: String,
    pub support_assist_enable_state: String, // ensure this is disabled
    #[serde(rename = "DefaultIPAddress")]
    pub default_ip_address: String,
    pub default_share_name: String,
    pub default_user_name: String,
    pub default_password: Option<String>,
    pub default_workgroup_name: String,
    #[serde(rename = "RegistrationID")]
    pub registration_id: String,
    #[serde(rename = "iDRACFirstPowerUpDateTime")]
    pub idrac_first_power_up_date_time: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellBmcNic {
    #[serde(rename = "DedicatedNICScanTime")]
    pub dedicated_nic_scan_time: i64,
    #[serde(rename = "MTU")]
    pub mtu: i64, // ensure this is correct
    #[serde(rename = "NumberOfLOM")]
    pub number_of_lom: Option<i64>,
    #[serde(rename = "SharedNICScanTime")]
    pub shared_nic_scan_time: i64,
    #[serde(rename = "VLanID")]
    pub vlan_id: i64,
    #[serde(rename = "VLanPriority")]
    pub vlan_priority: i64,
    #[serde(rename = "ActiveNIC")]
    pub active_nic: Option<String>,
    #[serde(rename = "ActiveSharedLOM")]
    pub active_shared_lom: Option<String>,
    pub auto_config: Option<String>,
    pub auto_detect: String,
    pub autoneg: String, // ensure this is enabled
    #[serde(rename = "DNSDomainFromDHCP")]
    pub dns_domain_from_dhcp: String,
    #[serde(rename = "DNSDomainNameFromDHCP")]
    pub dns_domain_name_from_dhcp: Option<String>,
    #[serde(rename = "DNSRegister")]
    pub dns_register: String,
    #[serde(rename = "DNSRegisterInterval")]
    pub dns_register_interval: Option<i64>,
    #[serde(rename = "DiscoveryLLDP")]
    pub discovery_lldp: Option<String>,
    pub duplex: String,
    pub enable: String, // ensure this is enabled
    pub failover: String,
    pub link_status: Option<String>,
    pub ping_enable: String,
    pub selection: Option<String>,
    pub speed: String,
    pub topology_lldp: Option<String>,
    #[serde(rename = "VLanEnable")]
    pub vlan_enable: String,
    #[serde(rename = "VLanPort")]
    pub vlan_port: Option<String>,
    #[serde(rename = "VLanSetting")]
    pub vlan_setting: Option<String>,
    #[serde(rename = "DNSDomainName")]
    pub dns_domain_name: String,
    #[serde(rename = "DNSRacName")]
    pub dns_rac_name: String,
    #[serde(rename = "MACAddress")]
    pub mac_address: String,
    #[serde(rename = "MACAddress2")]
    pub mac_address2: Option<String>,
    pub mgmt_iface_name: Option<String>,
    pub switch_connection: Option<String>,
    pub switch_port_connection: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellSysInfo {
    pub local_console_lock_out: i64,
    #[serde(rename = "POSTCode")]
    pub post_code: i64,
    pub system_rev: i64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellBmcIpv6 {
    #[serde(rename = "IPV6NumOfExtAddress")]
    pub num_of_ext_address: Option<i64>,
    pub prefix_length: i64,
    pub address1: String,
    pub address2: String,
    pub address3: String,
    pub address4: String,
    pub address5: String,
    pub address6: String,
    pub address7: String,
    pub address8: String,
    pub address9: String,
    pub address10: String,
    pub address11: String,
    pub address12: String,
    pub address13: String,
    pub address14: String,
    pub address15: String,
    #[serde(rename = "DHCPv6Address")]
    pub dhcpv6_address: Option<String>,
    #[serde(rename = "DNS1")]
    pub dns1: String,
    #[serde(rename = "DNS2")]
    pub dns2: String,
    #[serde(rename = "DUID")]
    pub duid: String,
    pub gateway: String,
    pub link_local_address: String,
    pub address_generation_mode: String,
    pub address_state: Option<String>,
    pub auto_config: String,
    #[serde(rename = "DNSFromDHCP6")]
    pub dns_from_dhcp6: String,
    pub enable: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellBmcIpv4 {
    #[serde(rename = "DHCPEnable")]
    pub dhcp_enable: String,
    #[serde(rename = "DNSFromDHCP")]
    pub dns_from_dhcp: String,
    pub enable: String,
    pub address: String,
    pub netmask: String,
    pub gateway: String,
    #[serde(rename = "DNS1")]
    pub dns1: String,
    #[serde(rename = "DNS2")]
    pub dns2: String,
    pub dup_addr_detected: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellUsers {
    pub privilege: i64,
    pub authentication_protocol: String,
    pub enable: String,
    pub ipmi_lan_privilege: String,
    pub ipmi_serial_privilege: String,
    pub privacy_protocol: String,
    pub protocol_enable: String,
    #[serde(rename = "Simple2FA")]
    pub simple_2fa: String,
    pub sol_enable: String,
    pub use_email: String,
    #[serde(rename = "UseSMS")]
    pub use_sms: String,
    pub email_address: String,
    #[serde(rename = "IPMIKey")]
    pub ipmi_key: String,
    #[serde(rename = "MD5v3Key")]
    pub md5_v3_key: String,
    #[serde(rename = "SHA1v3Key")]
    pub sha1_v3_key: String,
    #[serde(rename = "SHA256Password")]
    pub sha256_password: String,
    #[serde(rename = "SHA256PasswordSalt")]
    pub sha256_password_salt: String,
    #[serde(rename = "SMSNumber")]
    pub sms_number: String,
    pub user_name: String,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellSysLog {
    pub port: i64,
    pub power_log_interval: i64,
    pub power_log_enable: String,
    pub sys_log_enable: String, // ensure this is disabled
    pub server1: String,
    pub server2: String,
    pub server3: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellRedfishEventing {
    pub delivery_retry_attempts: i64,
    pub delivery_retry_interval_in_seconds: i64,
    pub ignore_certificate_errors: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellTime {
    pub day_light_offset: i64,
    pub time_zone_offset: i64,
    pub timezone: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellSsh {
    pub max_sessions: i64,
    pub port: i64,
    pub timeout: i64,
    pub enable: String,
    pub banner: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellSecurity {
    pub password_minimum_length: i64,
    #[serde(rename = "FIPSMode")]
    pub fips_mode: String,
    pub minimum_password_score: String,
    pub password_require_numbers: String,
    pub password_require_symbols: String,
    pub password_require_upper_case: String,
    pub password_require_regex: String,
    pub csr_common_name: String,
    pub csr_country_code: String,
    pub csr_email_addr: String,
    pub csr_locality_name: String,
    pub csr_organization_name: String,
    pub csr_organization_unit: String,
    pub csr_state_name: String,
    pub csr_subject_alt_name: String,
    pub csr_key_size: String,
    #[serde(rename = "FIPSVersion")]
    pub fips_version: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellWebServer {
    pub http_port: i64,
    pub https_port: i64,
    pub max_number_of_sessions: i64,
    pub timeout: i64,
    #[serde(rename = "BlockHTTPPort")]
    pub block_http_port: String,
    pub enable: String, // ensure this is enabled
    pub host_header_check: String,
    pub http2_enable: String,
    pub https_redirection: String, // ensure this is enabled
    pub lower_encryption_bit_length: String,
    #[serde(rename = "SSLEncryptionBitLength")]
    pub ssl_encryption_bit_length: String,
    #[serde(rename = "TLSProtocol")]
    pub tls_protocol: String,
    pub title_bar_option: String,
    pub title_bar_option_custom: String,
    pub custom_cipher_string: String,
    #[serde(rename = "ManualDNSEntry")]
    pub manual_dns_entry: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellSecurityCertificate {
    pub cert_valid_from: String,
    pub cert_valid_to: String,
    pub issuer_common_name: String,
    pub issuer_country_code: String,
    pub issuer_locality: String,
    pub issuer_organization: String,
    pub issuer_organizational_unit: String,
    pub issuer_state: String,
    pub serial_number: String, // not an identifier
    pub subject_common_name: String,
    pub subject_country_code: String,
    pub subject_locality: String,
    pub subject_organization: String,
    pub subject_organizational_unit: String,
    pub subject_state: String,
    pub certificate_instance: i64,
    pub certificate_type: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellPlatformCapability {
    #[serde(rename = "ASHRAECapable")]
    pub ashrae_capable: String,
    pub backup_restore_capable: String,
    #[serde(rename = "CUPSCapable")]
    pub cups_capable: String,
    pub front_panel_capable: String,
    #[serde(rename = "FrontPanelUSBCapable")]
    pub front_panel_usb_capable: String,
    #[serde(rename = "FrontPortUSBConfiguration")]
    pub front_port_usb_configuration: String,
    pub grid_current_cap_capable: String,
    #[serde(rename = "LCDCapable")]
    pub lcd_capable: String,
    pub live_scan_capable: String,
    #[serde(rename = "NicVLANCapable")]
    pub nic_vlan_capable: String,
    #[serde(rename = "PMBUSCapablePSU")]
    pub pmbus_capable_psu: String,
    pub power_budget_capable: String,
    pub power_monitoring_capable: String,
    #[serde(rename = "SerialDB9PCapable")]
    pub serial_db9p_capable: String,
    pub server_allocation_capable: String,
    pub system_current_cap_capable: String,
    pub user_power_cap_bound_capable: String,
    pub user_power_cap_capable: String,
    pub wi_fi_capable: String,
    #[serde(rename = "vFlashCapable")]
    pub vflash_capable: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellServiceModule {
    #[serde(rename = "ChipsetSATASupported")]
    pub chipset_sata_supported: String,
    #[serde(rename = "HostSNMPAlert")]
    pub host_snmp_alert: String,
    #[serde(rename = "HostSNMPGet")]
    pub host_snmp_get: String,
    #[serde(rename = "HostSNMPOMSAAlert")]
    pub host_snmp_omsa_alert: String,
    #[serde(rename = "LCLReplication")]
    pub lcl_replication: String,
    #[serde(rename = "OMSAPresence")]
    pub omsa_presence: String,
    #[serde(rename = "OSInfo")]
    pub os_info: String,
    #[serde(rename = "SSEventCorrelation")]
    pub ss_event_correlation: String,
    pub service_module_enable: String,
    pub service_module_state: String,
    #[serde(rename = "WMIInfo")]
    pub wmi_info: String,
    pub watchdog_recovery_action: String,
    pub watchdog_state: String,
    #[serde(rename = "iDRACHardReset")]
    pub idrac_hard_reset: String,
    #[serde(rename = "iDRACSSOLauncher")]
    pub idrac_sso_launcher: String,
    pub service_module_version: String,
    pub watchdog_reset_time: i64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellVirtualConsole {
    pub active_sessions: i64,
    pub max_sessions: i64,
    pub port: i64,
    pub timeout: i64,
    pub access_privilege: String,
    pub attach_state: String,
    pub close_unused_port: String,
    pub enable: String,
    pub encrypt_enable: String,
    pub local_disable: String,
    pub local_video: String,
    pub plugin_type: String,
    pub timeout_enable: String,
    pub web_redirect: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellVirtualMedia {
    pub active_sessions: i64,
    pub max_sessions: i64,
    pub attached: String,
    pub boot_once: String,
    pub enable: String, // ensure this is disabled
    pub encrypt_enable: String,
    pub floppy_emulation: String,
    pub key_enable: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellRacadm {
    pub max_sessions: i64,
    pub timeout: i64,
    pub enable: String, // ensure this is disabled
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellInfo {
    pub server_gen: String,
    #[serde(rename = "Type")]
    pub server_type: String,
    pub build: String,
    #[serde(rename = "CPLDVersion")]
    pub cpld_version: String, // audit, ensure this is >= min required
    pub description: String,
    #[serde(rename = "HWRev")]
    pub hw_rev: String,
    #[serde(rename = "IPMIVersion")]
    pub ipmi_version: String,
    pub name: String,
    pub product: String,
    pub rollback_build: String,
    pub rollback_version: String,
    pub version: String, // audit, ensure this is >= min required
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellIpmiLan {
    pub alert_enable: String,
    pub enable: String,
    pub priv_limit: String,
    pub community_name: String,
    pub encryption_key: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellIpmiSol {
    pub baud_rate: String, //SerialBaudRates,
    pub enable: EnabledDisabled,
    pub min_privilege: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellSerialRedirection {
    pub enable: EnabledDisabled, // ensure this is enabled
    pub quit_key: String,        // "^\\", set/store this in db for ssh proxy service
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellVncServer {
    pub active_sessions: i64,
    pub max_sessions: i64,
    pub port: i64,
    pub timeout: i64,
    pub enable: String, // ensure this is disabled
    pub lower_encryption_bit_length: String,
    #[serde(rename = "SSLEncryptionBitLength")]
    pub ssl_encryption_bit_length: String,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellOsBmc {
    pub admin_state: String,
    #[serde(rename = "PTCapability")]
    pub pt_capability: String,
    #[serde(rename = "PTMode")]
    pub pt_mode: String,
    pub usb_nic_ipv4_address_support: String,
    pub os_ip_address: String,
    pub usb_nic_ip_address: String,
    pub usb_nic_ip_v6_address: String,
    #[serde(rename = "UsbNicULA")]
    pub usb_nic_ula: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellRfs {
    pub attach_mode: String,
    pub enable: String, // ensure this is disabled
    pub ignore_cert_warning: String,
    pub media_attach_state: String,
    pub status: String,
    pub write_protected: String,
    pub image: String,
    pub user: String,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellSerial {
    // this is the idrac serial config, not for the x86
    pub history_size: i64,
    pub idle_timeout: i64,
    pub baud_rate: String, //SerialBaudRates,
    pub enable: String,
    pub flow_control: String,
    pub no_auth: String,
    pub command: String,
}

#[derive(Debug, Deserialize, Serialize, Copy, Clone, Eq, PartialEq)]
pub enum OemDellBootDevices {
    Normal,
    PXE,
    HDD,
    BIOS,
    FDD,
    SD,
    F10,
    F11,
}

impl fmt::Display for OemDellBootDevices {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellServerBoot {
    pub boot_once: EnabledDisabled,
    pub first_boot_device: OemDellBootDevices,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellLocalSecurity {
    pub local_config: String,
    pub preboot_config: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellLogging {
    #[serde(rename = "SELBufferType")]
    pub sel_buffer_type: String,
    #[serde(rename = "SELOEMEventFilterEnable")]
    pub sel_oem_event_filter_enable: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellUpdate {
    #[serde(rename = "FwUpdateTFTPEnable")]
    pub fw_update_tftp_enable: String,
    #[serde(rename = "FwUpdateIPAddr")]
    pub fw_update_ip_addr: String,
    pub fw_update_path: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellAttributes {
    #[serde(rename = "Lockdown.1.SystemLockdown")]
    pub system_lockdown: String, // ensure this is set
    #[serde(rename = "Redfish.1.Enable")]
    pub redfish_enable: String,

    #[serde(flatten, with = "prefix_ssh")]
    pub ssh: OemDellSsh, // ensure this is configured
    #[serde(flatten, with = "prefix_serial_redirection")]
    pub serial_redirection: OemDellSerialRedirection, // ensure this is configured

    #[serde(rename = "PCIeVDM.1.Enable")]
    pub pcie_vdm_enable: String,
    #[serde(rename = "IntegratedDatacenter.1.DiscoveryEnable")]
    pub integrated_datacenter_discovery_enable: String,
    #[serde(rename = "ASRConfig.1.Enable")]
    pub asr_config_enable: String,
    #[serde(rename = "SwitchConnectionView.1.Enable")]
    pub switch_connection_view_enable: String,
    #[serde(rename = "SecureDefaultPassword.1.ForceChangePassword")]
    pub force_change_password: String,
    #[serde(rename = "DefaultCredentialMitigationConfigGroup.1.DefaultCredentialMitigation")]
    pub default_credential_mitigation: String,
    #[serde(rename = "AutoOSLockGroup.1.AutoOSLockState")]
    pub auto_os_lock_state: String,

    #[serde(flatten, with = "prefix_nic")]
    pub nic: OemDellBmcNic,
    #[serde(flatten, with = "prefix_ipv4")]
    pub ipv4: OemDellBmcIpv4,
    #[serde(flatten, with = "prefix_ipv6")]
    pub ipv6: OemDellBmcIpv6,

    #[serde(flatten, with = "prefix_current_nic")]
    pub current_nic: OemDellBmcNic,
    #[serde(flatten, with = "prefix_current_ipv4")]
    pub current_ipv4: OemDellBmcIpv4,
    #[serde(flatten, with = "prefix_current_ipv6")]
    pub current_ipv6: OemDellBmcIpv6,

    #[serde(flatten, with = "prefix_info")]
    pub info: OemDellInfo,
    #[serde(flatten, with = "prefix_ipmi_lan")]
    pub ipmi_lan: OemDellIpmiLan,
    #[serde(flatten, with = "prefix_local_security")]
    pub local_security: OemDellLocalSecurity,
    #[serde(flatten, with = "prefix_logging")]
    pub logging: OemDellLogging,
    #[serde(flatten, with = "prefix_os_bmc")]
    pub os_bmc: OemDellOsBmc,
    #[serde(flatten, with = "prefix_platform_capability")]
    pub platform_capability: OemDellPlatformCapability,
    #[serde(flatten, with = "prefix_racadm")]
    pub racadm: OemDellRacadm,
    #[serde(flatten, with = "prefix_redfish_eventing")]
    pub redfish_eventing: OemDellRedfishEventing,
    #[serde(flatten, with = "prefix_rfs")]
    pub rfs: OemDellRfs,
    #[serde(flatten, with = "prefix_security")]
    pub security: OemDellSecurity,
    #[serde(flatten, with = "prefix_security_certificate1")]
    pub security_certificate1: OemDellSecurityCertificate,
    #[serde(flatten, with = "prefix_security_certificate2")]
    pub security_certificate2: OemDellSecurityCertificate,
    #[serde(flatten, with = "prefix_service_module")]
    pub service_module: OemDellServiceModule,
    #[serde(flatten, with = "prefix_serial")]
    pub serial: OemDellSerial,
    #[serde(flatten, with = "prefix_server_boot")]
    pub server_boot: OemDellServerBoot,
    #[serde(flatten, with = "prefix_sys_info")]
    pub sys_info: OemDellSysInfo,
    #[serde(flatten, with = "prefix_sys_log")]
    pub sys_log: OemDellSysLog,
    #[serde(flatten, with = "prefix_support_assist")]
    pub support_assist: OemDellSupportAssist,
    #[serde(flatten, with = "prefix_time")]
    pub time: OemDellTime,
    #[serde(flatten, with = "prefix_update")]
    pub update: OemDellUpdate,
    #[serde(flatten, with = "prefix_virtual_console")]
    pub virtual_console: OemDellVirtualConsole,
    #[serde(flatten, with = "prefix_virtual_media")]
    pub virtual_media: OemDellVirtualMedia,
    #[serde(flatten, with = "prefix_vnc_server")]
    pub vnc_server: OemDellVncServer,
    #[serde(flatten, with = "prefix_web_server")]
    pub web_server: OemDellWebServer,

    #[serde(flatten, with = "prefix_users1")]
    pub users1: OemDellUsers,
    #[serde(flatten, with = "prefix_users2")]
    pub users2: OemDellUsers,
    #[serde(flatten, with = "prefix_users3")]
    pub users3: OemDellUsers,
    #[serde(flatten, with = "prefix_users4")]
    pub users4: OemDellUsers,
    #[serde(flatten, with = "prefix_users5")]
    pub users5: OemDellUsers,
    #[serde(flatten, with = "prefix_users6")]
    pub users6: OemDellUsers,
    #[serde(flatten, with = "prefix_users7")]
    pub users7: OemDellUsers,
    #[serde(flatten, with = "prefix_users8")]
    pub users8: OemDellUsers,
    #[serde(flatten, with = "prefix_users9")]
    pub users9: OemDellUsers,
    #[serde(flatten, with = "prefix_users10")]
    pub users10: OemDellUsers,
    #[serde(flatten, with = "prefix_users11")]
    pub users11: OemDellUsers,
    #[serde(flatten, with = "prefix_users12")]
    pub users12: OemDellUsers,
    #[serde(flatten, with = "prefix_users13")]
    pub users13: OemDellUsers,
    #[serde(flatten, with = "prefix_users14")]
    pub users14: OemDellUsers,
    #[serde(flatten, with = "prefix_users15")]
    pub users15: OemDellUsers,
    #[serde(flatten, with = "prefix_users16")]
    pub users16: OemDellUsers,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellAttributesResult {
    #[serde(flatten)]
    pub odata: ODataLinks,
    pub attributes: OemDellAttributes,
    pub description: String,
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellBmcLockdown {
    #[serde(rename = "Lockdown.1.SystemLockdown")]
    pub system_lockdown: EnabledDisabled,
    #[serde(rename = "Racadm.1.Enable")]
    pub racadm_enable: EnabledDisabled,
    #[serde(flatten, with = "prefix_server_boot")]
    pub server_boot: OemDellServerBoot,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SetOemDellBmcLockdown {
    #[serde(rename = "@Redfish.SettingsApplyTime")]
    pub redfish_settings_apply_time: SetOemDellSettingsApplyTime,
    pub attributes: OemDellBmcLockdown,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellBmcRemoteAccess {
    #[serde(rename = "SSH.1.Enable")]
    pub ssh_enable: EnabledDisabled,
    #[serde(flatten, with = "prefix_serial_redirection")]
    pub serial_redirection: OemDellSerialRedirection,
    #[serde(rename = "IPMILan.1.Enable")]
    pub ipmi_lan_enable: EnabledDisabled,
    #[serde(flatten, with = "prefix_ipmi_lan")]
    pub ipmi_sol: OemDellIpmiSol,
    // in future add virtualconsole, virtualmedia, vncserver if needed
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellServerBootAttrs {
    #[serde(flatten, with = "prefix_server_boot")]
    pub server_boot: OemDellServerBoot,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SetOemDellFirstBootDevice {
    pub redfish_settings_apply_time: SetOemDellSettingsApplyTime,
    pub attributes: OemDellServerBootAttrs,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SetOemDellBmcRemoteAccess {
    #[serde(rename = "@Redfish.SettingsApplyTime")]
    pub redfish_settings_apply_time: SetOemDellSettingsApplyTime,
    pub attributes: OemDellBmcRemoteAccess,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ActionsManagerReset {
    pub target: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Action {
    #[serde(rename = "#Manager.Reset")]
    pub manager_reset: ActionsManagerReset,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Availableaction {
    pub action: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Commandshell {
    pub connect_types_supported: Vec<String>,
    pub enabled: Option<bool>,
    pub max_concurrent_sessions: i64,
    pub service_enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OemHpActionshpiloResetToFactoryDefault {
    #[serde(rename = "ResetType@Redfish.AllowableValues")]
    pub reset_type_redfish_allowable_values: Vec<String>,
    pub target: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OemHpAction {
    #[serde(rename = "#HpiLO.ClearRestApiState")]
    pub hpi_lo_clear_rest_api_state: ActionsManagerReset,
    #[serde(rename = "#HpiLO.ResetToFactoryDefaults")]
    pub hpi_lo_reset_to_factory_defaults: OemHpActionshpiloResetToFactoryDefault,
    #[serde(rename = "#HpiLO.iLOFunctionality")]
    pub hpi_lo_i_lo_functionality: ActionsManagerReset,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemHpAvailableactionsCapability {
    pub allowable_values: Vec<String>,
    pub property_name: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemHpAvailableaction {
    pub action: String,
    pub capabilities: Vec<OemHpAvailableactionsCapability>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemHpFederationconfig {
    #[serde(rename = "IPv6MulticastScope")]
    pub i_pv6_multicast_scope: String,
    pub multicast_announcement_interval: i64,
    pub multicast_discovery: String,
    pub multicast_time_to_live: i64,
    #[serde(rename = "iLOFederationManagement")]
    pub i_lo_federation_management: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemHpFirmwareCurrent {
    pub date: String,
    pub debug_build: bool,
    pub major_version: i64,
    pub minor_version: i64,
    pub time: String,
    pub version_string: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemHpFirmware {
    pub current: OemHpFirmwareCurrent,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemHpLicense {
    pub license_key: String,
    pub license_string: String,
    pub license_type: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemHpIloselftestresult {
    pub notes: String,
    pub self_test_name: String,
    pub status: String,
}
impl crate::common::Status for OemHpIloselftestresult {
    fn health(&self) -> String {
        self.status.to_owned()
    }

    fn state(&self) -> String {
        String::new()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemHp {
    #[serde(flatten)]
    pub oem_type: HpType,
    pub actions: OemHpAction,
    pub available_actions: Vec<OemHpAvailableaction>,
    pub clear_rest_api_status: String,
    pub federation_config: OemHpFederationconfig,
    pub firmware: OemHpFirmware,
    pub license: OemHpLicense,
    #[serde(rename = "RequiredLoginForiLORBSU")]
    pub required_login_fori_lorbsu: bool,
    #[serde(rename = "SerialCLISpeed")]
    pub serial_cli_speed: i64,
    #[serde(rename = "SerialCLIStatus")]
    pub serial_cli_status: String,
    #[serde(rename = "VSPLogDownloadEnabled")]
    pub vsp_log_download_enabled: bool,
    #[serde(rename = "iLOSelfTestResults")]
    pub i_lo_self_test_results: Vec<OemHpIloselftestresult>,
    #[serde(rename = "links", flatten)]
    pub links: LinkType,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDelliDracCard {
    #[serde(flatten)]
    pub odata: ODataLinks,
    pub description: String,
    #[serde(rename = "IPMIVersion")]
    pub ipmi_version: String,
    pub id: String,
    pub last_system_inventory_time: String,
    pub last_update_time: String,
    pub name: String,
    #[serde(rename = "URLString")]
    pub url_string: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDell {
    #[serde(rename = "DelliDRACCard")]
    pub dell_idrac_card: OemDelliDracCard,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemHpWrapper {
    pub hp: OemHp,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellWrapper {
    pub dell: OemDell,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Status {
    pub state: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ManagerHp {
    #[serde(flatten)]
    pub odata: ODataLinks,
    pub actions: Action,
    pub available_actions: Vec<Availableaction>,
    pub command_shell: Commandshell,
    pub description: String,
    pub ethernet_interfaces: ODataId,
    pub firmware: Firmware,
    pub firmware_version: String,
    pub graphical_console: Commandshell,
    pub id: String,
    pub log_services: ODataId,
    pub manager_type: String,
    pub name: String,
    pub network_protocol: ODataId,
    pub oem: OemHpWrapper,
    pub serial_console: Commandshell,
    pub status: Status,
    #[serde(rename = "Type")]
    pub root_type: String,
    #[serde(rename = "UUID")]
    pub uuid: String,
    pub virtual_media: ODataId,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ManagerDell {
    #[serde(flatten)]
    pub odata: ODataLinks,
    pub actions: Action,
    pub command_shell: Commandshell,
    pub description: String,
    pub ethernet_interfaces: ODataId,
    pub firmware_version: String,
    pub graphical_console: Commandshell,
    pub id: String,
    pub log_services: ODataId,
    pub manager_type: String,
    pub name: String,
    pub network_protocol: ODataId,
    pub oem: OemDellWrapper,
    pub serial_console: Commandshell,
    pub status: Status,
    #[serde(rename = "UUID")]
    pub uuid: String,
    pub virtual_media: ODataId,
}

impl StatusVec for ManagerHp {
    fn get_vec(&self) -> Vec<Box<dyn crate::common::Status>> {
        let mut v: Vec<Box<dyn crate::common::Status>> = Vec::new();
        for res in &self.oem.hp.i_lo_self_test_results {
            v.push(Box::new(res.clone()))
        }
        v
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Managers {
    #[serde(flatten)]
    pub odata: ODataLinks,
    pub description: String,
    pub members: Vec<ODataId>,
    pub name: String,
}

#[test]
fn test_manager_parser() {
    let test_data = include_str!("../tests/manager.json");
    let result: ManagerHp = serde_json::from_str(test_data).unwrap();
    println!("result: {:#?}", result);
    let test_data2 = include_str!("../tests/manager_dell.json");
    let result2: ManagerDell = serde_json::from_str(test_data2).unwrap();
    println!("result2: {:#?}", result2);
    let test_data3 = include_str!("../tests/manager_dell_attrs.json");
    let result3: OemDellAttributesResult = serde_json::from_str(test_data3).unwrap();
    println!("result3: {:#?}", result3);
}
