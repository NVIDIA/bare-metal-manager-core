use libredfish::{Config, Redfish};

fn main() -> Result<(), reqwest::Error> {
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    let mut conf = Config {
        user: None,
        endpoint: "".to_string(),
        password: None,
        port: None,
        system: "".to_string()
    };

    opts.optopt("H", "hostname", "specify hostname or IP address", "HOST");
    opts.optopt("U", "username", "specify authentication username", "USER");
    opts.optopt("P", "password", "specify authentication password", "PASS");
    opts.optopt("c", "cmd", "specify the command to run: off/on/cycle/reset/shutdown(graceful)/restart(graceful)/status/tpm_enable/tpm_disable/tpm_reset/serial_enable/lockdown_enable/lockdown_disable", "CMD");

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
                redfish.set_system_power(libredfish::system::SystemPowerControl::GracefulShutdown)?;
            }
            "restart" => {
                redfish.set_system_power(libredfish::system::SystemPowerControl::GracefulRestart)?;
            }
            "status" => {
                match redfish.get_system() {
                    Ok(system) => {
                        println!("System power status: {}", system.power_state);
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e.to_string());
                    }
                }

            }
            "tpm_enable" => {
                redfish.enable_tpm()?;
            }
            "tpm_disable" => {
                redfish.disable_tpm()?;
            }
            "tpm_reset" => {
                redfish.reset_tpm()?;
            }
            "serial_enable" => {
                redfish.setup_serial_console()?;
            }
            "lockdown_enable" => {
                redfish.enable_bios_lockdown()?;
            }
            "lockdown_disable" => {
                redfish.disable_bios_lockdown()?;
            }
            _ => {
                eprintln!("Unsupported command specified {}", args_given.opt_str("c").unwrap());
            }
        }
    }

    Ok(())
}

