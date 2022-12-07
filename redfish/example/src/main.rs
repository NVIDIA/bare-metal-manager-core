use libredfish::{Config, Redfish};

fn main() -> Result<(), reqwest::Error> {
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    let mut conf = Config {
        user: None,
        endpoint: "".to_string(),
        password: None,
        port: None,
        system: "".to_string(),
        manager: "".to_string(),
        vendor: libredfish::Vendor::Unknown,
    };

    opts.optopt("H", "hostname", "specify hostname or IP address", "HOST");
    opts.optopt("U", "username", "specify authentication username", "USER");
    opts.optopt("P", "password", "specify authentication password", "PASS");
    opts.optopt("c", "cmd", "specify the command to run: off/on/cycle/reset/shutdown(graceful)/restart(graceful)/status/tpm_enable/tpm_disable/tpm_reset/serial_enable/lockdown_enable/lockdown_disable/bios_attrs/bmc_attrs/boot_pxe/boot_hdd/boot_once_pxe/boot_once_hdd", "CMD");

    let args_given = opts.parse(&args[1..]).unwrap();
    if args_given.opt_present("H") {
        conf.endpoint = args_given.opt_str("H").unwrap();
    }
    if args_given.opt_present("U") {
        conf.user = Some(args_given.opt_str("U").unwrap());
    }
    if args_given.opt_present("P") {
        conf.password = Some(args_given.opt_str("P").unwrap());
    }

    let mut redfish = Redfish::new(conf);

    redfish.get_system_id()?;
    redfish.get_manager_id()?;

    if args_given.opt_present("c") {
        match args_given.opt_str("c").unwrap().as_str() {
            "off" => {
                redfish.set_system_power(libredfish::system::SystemPowerControl::ForceOff)?;
            }
            "on" => {
                redfish.set_system_power(libredfish::system::SystemPowerControl::On)?;
            }
            "cycle" => {
                redfish.set_system_power(libredfish::system::SystemPowerControl::PowerCycle)?;
            }
            "reset" => {
                redfish.set_system_power(libredfish::system::SystemPowerControl::ForceRestart)?;
            }
            "shutdown" => {
                redfish
                    .set_system_power(libredfish::system::SystemPowerControl::GracefulShutdown)?;
            }
            "restart" => {
                redfish
                    .set_system_power(libredfish::system::SystemPowerControl::GracefulRestart)?;
            }
            "status" => match redfish.get_system() {
                Ok(system) => {
                    println!("System power status: {}", system.power_state);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                }
            },
            "tpm_enable" => {
                redfish.enable_tpm()?;
                println!("BIOS settings changes require system restart");
            }
            "tpm_disable" => {
                redfish.disable_tpm()?;
                println!("BIOS settings changes require system restart");
            }
            "tpm_reset" => {
                redfish.reset_tpm()?;
                println!("BIOS settings changes require system restart");
            }
            "serial_enable" => {
                redfish.setup_bmc_remote_access()?;
                redfish.setup_serial_console()?;
                println!("BIOS settings changes require system restart");
            }
            "lockdown_enable" => {
                redfish.enable_bios_lockdown()?;
                redfish.enable_bmc_lockdown()?;
                println!("BIOS settings changes require system restart");
            }
            "lockdown_disable" => {
                redfish.disable_bmc_lockdown()?;
                redfish.disable_bios_lockdown()?;
                println!("BIOS settings changes require system restart");
            }
            "bios_attrs" => match redfish.get_bios_data() {
                Ok(bios) => {
                    println!("{:?}", bios);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                }
            },
            "bmc_attrs" => match redfish.get_bmc_data() {
                Ok(bmc) => {
                    println! {"{:?}", bmc};
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                }
            },
            "boot_pxe" => {
                return redfish.set_boot_first(libredfish::manager::OemDellBootDevices::PXE, false);
            }
            "boot_hdd" => {
                return redfish.set_boot_first(libredfish::manager::OemDellBootDevices::HDD, false);
            }
            "boot_once_pxe" => {
                return redfish.set_boot_first(libredfish::manager::OemDellBootDevices::PXE, true);
            }
            "boot_once_hdd" => {
                return redfish.set_boot_first(libredfish::manager::OemDellBootDevices::HDD, true);
            }
            _ => {
                eprintln!(
                    "Unsupported command specified {}",
                    args_given.opt_str("c").unwrap()
                );
            }
        }
    }

    Ok(())
}
