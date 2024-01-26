#[derive(Default)]
struct InterfaceManager {
    known_interfaces: Vec<String>,
}

impl InterfaceManager {
    pub fn run(&self) {
        let handle: std::thread::JoinHandle<_> = std::thread::spawn(move || {
            let last_interface_check = Instant::now();
            let interval = Duration::from_secs(10);
            loop {
                let elapsed = last_interface_check.elapsed();

                if elapsed > interval {
                } else {
                    std::thread::sleep(interval - elapsed);
                }
            }
        });

        handle.join();
    }
}
