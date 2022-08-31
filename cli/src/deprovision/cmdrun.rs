use std::process::Command;

pub fn run_prog(cmd: String) -> Result<String, String> {
    let mut cmdpar = cmd.split(' ');
    let mut runcmd = Command::new(cmdpar.next().unwrap());
    for par in cmdpar {
        runcmd.arg(par);
    }
    let stdout = match runcmd.output() {
        Ok(output) => {
            if output.status.success() {
                output.stdout
            } else {
                return Err(format!(
                    "Bad exit code: CMD=\"{}\" ERROR=\"{}\"",
                    cmd, output.status
                ));
            }
        }
        Err(errmsg) => {
            return Err(format!("Cant run: CMD=\"{}\" ERROR=\"{}\"", cmd, errmsg));
        }
    };
    Ok(String::from_utf8_lossy(&stdout).to_string())
}
