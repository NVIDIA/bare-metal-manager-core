//! `cargo run --example decode --features binary-format < INPUT_FILE > OUTPUT_FILE`
use bytecodec::io::IoDecodeExt;
use bytecodec::null::NullDecoder;
use patricia_tree::{node::NodeDecoder, PatriciaSet};

fn main() {
    let mut decoder = NodeDecoder::new(NullDecoder);
    let node = decoder.decode_exact(std::io::stdin()).unwrap();
    let set = PatriciaSet::from(node);
    for s in set.iter() {
        println!("{}", std::str::from_utf8(&s).unwrap());
    }
}
