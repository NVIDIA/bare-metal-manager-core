use crate::duppet::{self, SyncOptions};
use crate::periodic_config_fetcher::PeriodicConfigFetcher;
use rpc::uuid::machine::MachineId;
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;

pub fn main_sync(
    sync_options: SyncOptions,
    machine_id: &MachineId,
    periodic_config_fetcher: &PeriodicConfigFetcher,
) {
    // Sync out all duppet-managed config files. This can be called as part of
    // main_loop running if we want (and can also be called willy nilly with
    // ad-hoc sets of files, including whenever the nvue config changes if we
    // wanted to pull it in), but for now we just do this one duppet sync
    // during setup_and_run. Current files being managed are:
    //
    // - /etc/cron.daily/apt-clean
    // - /etc/dhcp/dhclient-exit-hooks.d/ntpsec
    // - /run/otelcol-contrib/machine-id
    // - /run/otelcol-contrib/host-machine-id
    let duppet_files: HashMap<PathBuf, duppet::FileSpec> = HashMap::from([
        (
            "/etc/cron.daily/apt-clean".into(),
            duppet::FileSpec::new_with_perms(include_str!("../templates/apt-clean"), 0o755),
        ),
        (
            "/etc/dhcp/dhclient-exit-hooks.d/ntpsec".into(),
            duppet::FileSpec::new_with_perms(include_str!("../templates/ntpsec"), 0o644),
        ),
        (
            "/run/otelcol-contrib/machine-id".into(),
            duppet::FileSpec::new_with_content(build_otel_machine_id_file(machine_id)),
        ),
        (
            "/run/otelcol-contrib/host-machine-id".into(),
            duppet::FileSpec::new_with_content(build_otel_host_machine_id_file(
                periodic_config_fetcher
                    .get_host_machine_id()
                    .map(|id| Cow::Owned(id.to_string()))
                    .unwrap_or(Cow::Borrowed("")),
            )),
        ),
    ]);
    if let Err(e) = duppet::sync(duppet_files, sync_options) {
        tracing::error!("error during duppet run: {}", e)
    }
}

// Write "machine.id=<value>" to a file so the OpenTelemetry collector can apply it as a resource
// attribute.
pub fn build_otel_machine_id_file(machine_id: &MachineId) -> String {
    format!("machine.id={machine_id}\n")
}

// Write "host.machine.id=<value>" to a file so the OpenTelemetry collector can apply it as a
// resource attribute.
pub fn build_otel_host_machine_id_file(host_machine_id: Cow<str>) -> String {
    format!("host.machine.id={host_machine_id}\n")
}
