use std::collections::HashMap;
use std::fs::{remove_file, File};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use dhcp::mock_api_server;
use dhcproto::v4::relay::RelayInfo;
use dhcproto::v4::{relay, Message};
use dhcproto::{v4, Decodable, Decoder, Encodable, Encoder};
use serde_json::json;

const DHCP_IN_PORT: &str = "6767";
const DHCP_OUT_PORT: &str = "6868";
const KEA_CONF_PATH: &str = "/tmp/test_kea_multithreaded.conf";
const RELAY_IP: &str = "127.1.2.3";

// Must be u8 to be used a idx (last part of MAC and link IP)
// Must not exceed Kea config 'packet-queue-size', below, or packets  will be dropped.
const NUM_THREADS: u8 = 10;
const NUM_MSGS_PER_THREAD: usize = 100;
const NUM_EXPECTED: u64 = NUM_THREADS as u64 * NUM_MSGS_PER_THREAD as u64;

const READ_TIMEOUT: Duration = Duration::from_millis(500);

// Start a real Kea process, configured to be multi threaded, and send it some DISCOVERY messages from multiple threads.
// We pretend to be the relay because our hooks only accepted relayed packets.
//
// Kea should receive the packets, call our hooks, which should call MockAPIServer and then respond to
// the relay (aka gateway), which is us.
#[test]
fn test_real_kea_multithreaded() -> Result<(), anyhow::Error> {
    // Start multi-threaded mock API server. The hooks call this over the network.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let api_server = rt.block_on(mock_api_server::MockAPIServer::start());

    // Start Kea process. Stops on drop.
    let _kea = Kea::start(api_server.local_http_addr())?;

    // UDP socket to Kea. We're pretending to be dhcp-relay.
    let socket = UdpSocket::bind(format!("{RELAY_IP}:{DHCP_OUT_PORT}"))?;
    socket.connect(format!("127.0.0.1:{DHCP_IN_PORT}"))?;
    socket.set_read_timeout(Some(READ_TIMEOUT))?;

    // The first packet doesn't get a response. I don't know why. dhcp-relay also sends two.
    // So sacrifice a packet, and wait to be sure it's the first packet received by Kea.
    let mut msg = DHCPFactory::discover(0);
    msg.set_xid(0);
    let pkt = DHCPFactory::encode(msg)?;
    socket.send(&pkt)?;
    thread::sleep(Duration::from_millis(20));

    let socket = Arc::new(socket);
    let recv_packets = Arc::new(AtomicU64::new(0));
    thread::scope(|s| {
        // idx -> mpsc::channel.
        // Sender blocks on this once it sends DISCOVERY. Receiver unblocks it on matching OFFER.
        let mut chan_map = HashMap::with_capacity(NUM_THREADS as usize);

        // In case of packet loss we need to abort all threads.
        // thread::scope join's them all on exit.
        let should_stop = Arc::new(AtomicBool::new(false));

        // Multiple send threads

        // Start from 1 because idx 0 was the sacrifice
        for idx in 1..=NUM_THREADS {
            let inner_socket = socket.clone();
            let s_should_stop = should_stop.clone();
            let (unblock, block) = channel();
            s.spawn(move || {
                // wait for receiver to start and avoid thundering herd
                thread::sleep(Duration::from_millis(50 + idx as u64));
                let msg_orig = DHCPFactory::discover(idx);
                let mut sent = 0;
                while sent < NUM_MSGS_PER_THREAD && !s_should_stop.load(Ordering::Relaxed) {
                    let mut msg = msg_orig.clone();
                    msg.set_xid((sent as u32) << 8 | idx as u32);
                    let pkt = DHCPFactory::encode(msg).unwrap();
                    inner_socket.send(&pkt).unwrap();
                    sent += 1;
                    // wait for OFFER response to arrive
                    _ = block.recv();
                }
            });
            chan_map.insert(idx, unblock);
        }

        // Single receive thread

        let socket_recv = socket.clone();
        let r_packets = recv_packets.clone();
        let _receiver = s.spawn(move || {
            let mut recv_buf = [0u8; 1500]; // packet is 470 bytes, but allow for full MTU
            let mut received = 0;
            while received < NUM_EXPECTED {
                let n = match socket_recv.recv(&mut recv_buf) {
                    Ok(n) => n,
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        // Socket read timeout, indicates packets loss.
                        break;
                    }
                    Err(err) => {
                        panic!("socket recv unhandled error: {err}");
                    }
                };
                let msg = v4::Message::decode(&mut Decoder::new(&recv_buf[..n])).unwrap();
                assert_eq!(msg.opts().msg_type().unwrap(), v4::MessageType::Offer);
                let idx = msg.xid() as u8;
                received += 1;
                match chan_map.get(&idx) {
                    Some(handle) => _ = handle.send(()),
                    None => {
                        println!("idx:{idx} missing in thread handle map for {}", msg);
                    }
                }
            }
            r_packets.store(received, Ordering::Relaxed);
            // unblock senders
            should_stop.store(true, Ordering::Relaxed);
            chan_map.values().for_each(|c| {
                _ = c.send(());
            });
        });

        // wait for all the OFFER responses to be received. scope does this for us.
    });
    assert_eq!(
        recv_packets.load(Ordering::Relaxed),
        NUM_EXPECTED,
        "Receive thread returned early because one or more packets were lost."
    );

    // Each thread only triggered one backend call because the other messages used the cache.
    let api_calls = api_server.calls_for(mock_api_server::ENDPOINT_DISCOVER_DHCP) as u8;
    assert_eq!(api_calls, NUM_THREADS + 1); // +1 for the sacrificial message

    Ok(())
}

struct DHCPFactory {}

impl DHCPFactory {
    fn encode(msg: Message) -> Result<Vec<u8>, anyhow::Error> {
        let mut buf = Vec::with_capacity(300); // msg is 279 bytes
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        Ok(buf)
    }

    // Make and encode a relayed DHCP_DISCOVER packet
    // The idx is used as the last byte of the MAC and Link addresses to make them unique.
    fn discover(idx: u8) -> Message {
        // 0x02 prefix is a 'locally administered address'
        let mac = vec![0x02, 0x00, 0x00, 0x00, 0x00, idx];

        // Five colon separated fields. Our parser (vendor_class.rs) only uses fields 0 and 2.
        // 7 is MachineArchitecture::EfiX64, HTTP version
        let uefi_vendor_class = b"HTTPClient::7::".to_vec();

        let mut relay_agent = relay::RelayAgentInformation::default();
        relay_agent.insert(RelayInfo::AgentCircuitId(b"eth0".to_vec()));
        let link_address = [172, 16, 42, idx];
        relay_agent.insert(RelayInfo::LinkSelection(link_address.into()));

        let gateway_ip = RELAY_IP.parse::<Ipv4Addr>().unwrap();

        let mut msg = v4::Message::default();
        let opts = msg
            .set_chaddr(&mac)
            .set_giaddr(gateway_ip) // This says message was relayed
            .set_hops(1) // a real relayed packet would have this. not necessary for the test.
            .opts_mut();
        use v4::DhcpOption::*;
        opts.insert(ClassIdentifier(uefi_vendor_class)); // 60
        opts.insert(RelayAgentInformation(relay_agent)); // 82
        opts.insert(ClientSystemArchitecture(v4::Architecture::Intelx86PC)); // 93
        opts.insert(MessageType(v4::MessageType::Discover));

        msg
    }
}

struct Kea {
    process: Child,
    conf_path: String,
}

impl Kea {
    // Start the Kea DHCP server as a sub-process and return a handle to it
    // Stops when the returned object is dropped.
    fn start(api_server_url: &str) -> Result<Kea, anyhow::Error> {
        let conf_path = KEA_CONF_PATH.to_string();
        let kea_conf = Kea::config(api_server_url);

        let mut kea_conf_file = File::create(&conf_path)?;
        kea_conf_file.write_all(kea_conf.as_bytes())?;
        drop(kea_conf_file);

        let process = Kea::run(KEA_CONF_PATH)?;
        Ok(Kea { process, conf_path })
    }

    fn run(conf_path: &str) -> Result<Child, anyhow::Error> {
        let mut process = Command::new("/usr/sbin/kea-dhcp4")
            .env("KEA_PIDFILE_DIR", "/tmp")
            .env("KEA_LOCKFILE_DIR", "/tmp")
            .arg("-c")
            .arg(conf_path)
            .arg("-p")
            .arg(DHCP_IN_PORT)
            .arg("-P")
            .arg(DHCP_OUT_PORT)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdout = BufReader::new(process.stdout.take().unwrap());
        let stderr = BufReader::new(process.stderr.take().unwrap());
        thread::spawn(move || {
            for line in stdout.lines() {
                println!("KEA STDOUT: {}", line.unwrap());
            }
        });
        thread::spawn(move || {
            for line in stderr.lines() {
                println!("KEA STDOUT: {}", line.unwrap());
            }
        });
        thread::sleep(Duration::from_millis(500)); // let Kea start
        Ok(process)
    }

    fn config(api_server_url: &str) -> String {
        let hook_lib_d = format!("{}/../target/debug/libdhcp.so", env!("CARGO_MANIFEST_DIR"));
        let hook_lib_r = format!(
            "{}/../target/release/libdhcp.so",
            env!("CARGO_MANIFEST_DIR")
        );
        let hook_lib = if Path::new(&hook_lib_r).exists() {
            hook_lib_r
        } else if Path::new(&hook_lib_d).exists() {
            hook_lib_d
        } else {
            // If `cargo build` has not been run yet (after a `cargo clean`), the `build.rs` script won't have
            // generated libdhcp.so. So we do it ourselves.
            println!(
                "Could not find Kea hooks dynamic library at '{}'. Building.",
                hook_lib_d
            );
            test_cdylib::build_current_project();
            hook_lib_d
        };

        let conf = json!({
        "Dhcp4": {
            "interfaces-config": {
                "interfaces": [ "lo" ],
                "dhcp-socket-type": "udp"
            },
            "lease-database": {
                "type": "memfile",
                "persist": false,
                "lfc-interval": 3600
            },
            "multi-threading": {
                "enable-multi-threading": true,
                "thread-pool-size": 4,
                "packet-queue-size": 28,
                "user-context": {
                    "comment": "Values above are Kea recommendations for memfile backend",
                    "url": "https://kea.readthedocs.io/en/kea-2.2.0/arm/dhcp4-srv.html#multi-threading-settings-with-different-database-backends"
                }
            },
            "renew-timer": 900,
            "rebind-timer": 1800,
            "valid-lifetime": 3600,
            "hooks-libraries": [
                {
                    "library": hook_lib,
                    "parameters": {
                        "carbide-api-url": api_server_url,
                        "carbide-nameservers": "1.1.1.1,8.8.8.8",
                    }
                }
            ],
            "subnet4": [
                {
                    "subnet": "0.0.0.0/0",
                    "pools": [{
                        "pool": "0.0.0.0-255.255.255.255"
                    }]
                }
            ],
            "user-context": {
                "comment": "Change severity below to DEBUG and run 'cargo test -- --nocapture' for verbose test output",
            },
            "loggers": [
                {
                    "name": "kea-dhcp4",
                    "output_options": [{"output": "stdout"}],
                    "severity": "WARN",
                    "debuglevel": 99
                },
                {
                    "name": "kea-dhcp4.carbide-rust",
                    "output_options": [{"output": "stdout"}],
                    "severity": "WARN",
                    "debuglevel": 10
                },
                {
                    "name": "kea-dhcp4.carbide-callouts",
                    "output_options": [{"output": "stdout"}],
                    "severity": "FATAL",
                    "debuglevel": 10
                }
            ]
        }
        });
        conf.to_string()
    }
}

impl Drop for Kea {
    fn drop(&mut self) {
        // Rust stdlib can only send a KILL (9) to sub-process. Thankfully dhcp already depends on
        // libc so we can use that.
        unsafe {
            libc::kill(self.process.id() as i32, libc::SIGTERM);
        }
        thread::sleep(Duration::from_millis(100));
        if let Ok(None) = self.process.try_wait() {
            self.process.kill().unwrap(); // -9
        }

        remove_file(&self.conf_path).unwrap();
    }
}
