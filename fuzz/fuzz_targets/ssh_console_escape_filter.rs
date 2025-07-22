#![no_main]
use libfuzzer_sys::fuzz_target;
use ssh_console::bmc_vendor::{EscapeSequence, IPMITOOL_ESCAPE_SEQUENCE};

fuzz_target!(|data: &[u8]| {
    static SINGLE_SEQUENCE: u8 = 0x1b;
    static PAIR_SEQUENCE: (u8, &[u8]) = (0x1b, &[0x28]);
    static IPMITOOL_SEQUENCE_TRAILS: &[u8] = &[b'.', b'B', b'?', 0x1a, 0x18];
    assert!(
        !EscapeSequence::Single(SINGLE_SEQUENCE)
            .filter_escape_sequences(data, false)
            .0
            .contains(&SINGLE_SEQUENCE)
    );

    for result in [
        // Pair, no pending
        EscapeSequence::Pair(PAIR_SEQUENCE).filter_escape_sequences(data, false),
        // Pair, with pending byte from last chunk
        EscapeSequence::Pair(PAIR_SEQUENCE).filter_escape_sequences(data, true),
    ] {
        assert!(
            !result
                .0
                .windows(2)
                .any(|w| w[0] == PAIR_SEQUENCE.0 && w[1] == PAIR_SEQUENCE.1[0])
        );
    }

    for result in [
        // Pair, no pending
        IPMITOOL_ESCAPE_SEQUENCE.filter_escape_sequences(data, false),
        // Pair, with pending byte from last chunk
        IPMITOOL_ESCAPE_SEQUENCE.filter_escape_sequences(data, true),
    ] {
        for &trailing in IPMITOOL_SEQUENCE_TRAILS {
            assert!(
                !result
                    .0
                    .windows(2)
                    .any(|w| w[0] == b'~' && w[1] == trailing)
            );
        }
    }
});
