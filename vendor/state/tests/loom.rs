#![cfg(loom)]

use loom::sync::Arc;
use loom::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use loom::thread;

#[test]
fn init_exclusive() {
    use state::private::init::Init;

    const THREADS: usize = 2;

    loom::model(|| {
        let init = Arc::new(Init::new());
        let value = Arc::new(AtomicUsize::new(0));

        let mut threads = vec![];
        for _ in 1..(THREADS + 1) {
            let init = init.clone();
            let value = value.clone();
            let thread = thread::spawn(move || {
                if init.needed() {
                    value.fetch_add(1, Relaxed);
                    init.mark_complete();
                }
            });

            threads.push(thread);
        }

        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(value.load(Relaxed), 1);
    });
}

#[test]
fn init_completed() {
    use state::private::init::Init;

    const THREADS: usize = 2;

    loom::model(|| {
        let init = Arc::new(Init::new());
        let value = Arc::new(AtomicUsize::new(0));

        let mut threads = vec![];
        for _ in 1..(THREADS + 1) {
            let init = init.clone();
            let value = value.clone();
            let thread = thread::spawn(move || {
                if init.has_completed() {
                    assert_eq!(value.load(Relaxed), 1);
                }

                if init.needed() {
                    value.fetch_add(1, Relaxed);
                    init.mark_complete();
                }
            });

            threads.push(thread);
        }

        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(value.load(Relaxed), 1);
    });
}

#[test]
fn storage() {
    use state::Storage;

    const THREADS: usize = 2;

    loom::model(|| {
        let storage = Arc::new(Storage::<u8>::new());

        let mut threads = vec![];
        for _ in 1..(THREADS + 1) {
            let storage = storage.clone();
            let thread = thread::spawn(move || {
                storage.set(10);
                assert_eq!(storage.try_get(), Some(&10));
                assert!(!storage.set(20));
                assert_eq!(storage.try_get(), Some(&10));
            });

            threads.push(thread);
        }

        for thread in threads {
            thread.join().unwrap();
        }
    });
}

#[test]
fn container1() {
    use state::Container;

    const THREADS: usize = 2;

    loom::model(|| {
        let container = Arc::new(<Container![Send + Sync]>::new());

        let mut threads = vec![];
        for _ in 1..(THREADS + 1) {
            let container = container.clone();
            let thread = thread::spawn(move || {
                assert_eq!(container.try_get::<isize>(), None);
                container.set::<usize>(10);
                assert_eq!(container.try_get::<usize>(), Some(&10));
                assert!(!container.set::<usize>(11));
                assert_eq!(container.try_get::<usize>(), Some(&10));
            });

            threads.push(thread);
        }

        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(container.len(), 1);
    });
}

#[test]
fn container2() {
    use state::Container;

    const THREADS: usize = 2;

    loom::model(|| {
        let container = Arc::new(<Container![Send + Sync]>::new());

        let mut threads = vec![];
        for _ in 1..(THREADS + 1) {
            let container = container.clone();
            let thread = thread::spawn(move || {
                if container.try_get::<Box<usize>>().is_some() {
                    assert!(!container.set::<Box<usize>>(Box::new(10)));
                }

                container.set::<Box<usize>>(Box::new(10));
                assert_eq!(**container.try_get::<Box<usize>>().unwrap(), 10);
            });

            threads.push(thread);
        }

        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(container.len(), 1);
    });
}
