use crate::node::{Flags, Node};
use bytecodec::combinator::Omittable;
use bytecodec::fixnum::{U16beDecoder, U16beEncoder, U8Decoder, U8Encoder};
use bytecodec::tuple::{TupleDecoder, TupleEncoder};
use bytecodec::{ByteCount, Decode, DecodeExt, Encode, Eos, ErrorKind, Result};
use std::cmp;

/// `[cfg(feature = "binary-format")]` Binary decoder for `Node`.
///
/// # Binary format
///
/// ```text
/// const FLAG_HAS_VALUE: u8 = 0b0000_0010;
/// const FLAG_HAS_CHILD: u8 = 0b0000_1000;
/// const FLAG_HAS_SIBLING: u8 = 0b0010_0000;
///
/// struct BinNode {
///     flags: u8,
///     label_len: u8,
///     level: u16 // Big Endian
///     label: [u8; label_len],
///     value: Option<V::Item>,
///     child: Option<Node>,
///     sibling: Option<Node>
/// }
/// ```
#[derive(Debug, Default)]
pub struct NodeDecoder<V: Decode> {
    stack: Vec<(u16, Node<V::Item>)>,
    node: Option<(u16, Node<V::Item>)>,
    label_offset: usize,
    header_decoder: HeaderDecoder,
    value_decoder: Omittable<V>,
    decoded: Option<Node<V::Item>>,
}
impl<V: Decode> NodeDecoder<V> {
    /// Makes a new `NodeDecoder` instance.
    pub fn new(value_decoder: V) -> Self {
        NodeDecoder {
            stack: Vec::new(),
            node: None,
            label_offset: 0,
            header_decoder: HeaderDecoder::default(),
            value_decoder: value_decoder.omit(false),
            decoded: None,
        }
    }
}
impl<V: Decode> Decode for NodeDecoder<V> {
    type Item = Node<V::Item>;

    fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
        if self.is_idle() {
            return Ok(0);
        }

        let mut offset = 0;
        loop {
            if self.node.is_none() {
                bytecodec_try_decode!(self.header_decoder, offset, buf, eos);
                let header = track!(self.header_decoder.finish_decoding())?;
                let node = Node::new_for_decoding(header.flags, header.label_len);
                self.value_decoder
                    .do_omit(!node.flags().contains(Flags::VALUE_ALLOCATED));
                self.node = Some((header.level, node));
            }
            {
                let node = &mut self.node.as_mut().expect("Never fails").1;
                if self.label_offset < node.label().len() {
                    let size = cmp::min(buf.len() - offset, node.label().len() - self.label_offset);
                    (&mut node.label_mut()[self.label_offset..][..size])
                        .copy_from_slice(&buf[offset..][..size]);
                    offset += size;
                    self.label_offset += size;
                    if self.label_offset < node.label().len() {
                        break;
                    }
                }
            }

            bytecodec_try_decode!(self.value_decoder, offset, buf, eos);
            let value = track!(self.value_decoder.finish_decoding())?;
            let (level, mut node) = self.node.take().expect("Never fails");
            if let Some(value) = value {
                node.set_value(value);
            }
            self.label_offset = 0;

            self.stack.push((level, node));
            while let Some(node) = self.stack.pop() {
                let flags = node.1.flags();
                let has_next = (flags.contains(Flags::CHILD_ALLOCATED)
                    && !flags.contains(Flags::CHILD_INITIALIZED))
                    || (flags.contains(Flags::SIBLING_ALLOCATED)
                        && !flags.contains(Flags::SIBLING_INITIALIZED));
                if has_next {
                    self.stack.push(node);
                    break;
                }
                if let Some(pred) = self.stack.last_mut() {
                    if node.0 == pred.0 {
                        pred.1.set_sibling(node.1);
                    } else {
                        track_assert_eq!(pred.0 + 1, node.0, ErrorKind::InvalidInput);
                        pred.1.set_child(node.1);
                    }
                } else {
                    track_assert_eq!(node.0, 0, ErrorKind::InvalidInput);
                    self.decoded = Some(node.1);
                    return Ok(offset);
                }
            }
        }
        Ok(offset)
    }

    fn finish_decoding(&mut self) -> Result<Self::Item> {
        let item = track_assert_some!(self.decoded.take(), ErrorKind::IncompleteDecoding);
        Ok(item)
    }

    fn requiring_bytes(&self) -> ByteCount {
        if self.is_idle() {
            ByteCount::Finite(0)
        } else {
            ByteCount::Unknown
        }
    }

    fn is_idle(&self) -> bool {
        self.decoded.is_some()
    }
}

/// `[cfg(feature = "binary-format")]` Binary encoder for `Node`.
///
/// # Binary format
///
/// ```text
/// const FLAG_HAS_VALUE: u8 = 0b0000_0010;
/// const FLAG_HAS_CHILD: u8 = 0b0000_1000;
/// const FLAG_HAS_SIBLING: u8 = 0b0010_0000;
///
/// struct BinNode {
///     flags: u8,
///     label_len: u8,
///     level: u16 // Big Endian
///     label: [u8; label_len],
///     value: Option<V::Item>,
///     child: Option<Node>,
///     sibling: Option<Node>
/// }
/// ```
#[derive(Debug, Default)]
pub struct NodeEncoder<V: Encode> {
    stack: Vec<(u16, Node<V::Item>)>,
    header_encoder: HeaderEncoder,
    label_offset: usize,
    value_encoder: V,
    in_progress: bool,
}
impl<V: Encode> NodeEncoder<V> {
    /// Makes a new `NodeEncoder` instance.
    pub fn new(value_encoder: V) -> Self {
        NodeEncoder {
            stack: Vec::new(),
            header_encoder: HeaderEncoder::default(),
            label_offset: 0,
            value_encoder,
            in_progress: false,
        }
    }
}
impl<V: Encode> Encode for NodeEncoder<V> {
    type Item = Node<V::Item>;

    fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
        let mut offset = 0;
        while !self.stack.is_empty() {
            if !self.in_progress {
                self.in_progress = true;
                let &mut (level, ref mut node) = self.stack.last_mut().expect("Never fails");
                let header = Header::new(level, node);
                track!(self.header_encoder.start_encoding(header))?;
                self.label_offset = 0;
                if let Some(v) = node.take_value() {
                    track!(self.value_encoder.start_encoding(v))?;
                }
            }

            if !self.header_encoder.is_idle() {
                offset += track!(self.header_encoder.encode(&mut buf[offset..], eos))?;
                if !self.header_encoder.is_idle() {
                    return Ok(offset);
                };
            }
            {
                let node = &self.stack.last().expect("Never fails").1;
                if self.label_offset < node.label().len() {
                    let size = cmp::min(buf.len() - offset, node.label().len() - self.label_offset);
                    (&mut buf[offset..][..size])
                        .copy_from_slice(&node.label()[self.label_offset..][..size]);
                    offset += size;
                    self.label_offset += size;
                    if self.label_offset < node.label().len() {
                        return Ok(offset);
                    }
                }
            }
            if !self.value_encoder.is_idle() {
                offset += track!(self.value_encoder.encode(&mut buf[offset..], eos))?;
                if !self.value_encoder.is_idle() {
                    return Ok(offset);
                }
            }

            let (level, mut node) = self.stack.pop().expect("Never fails");
            if let Some(n) = node.take_sibling() {
                self.stack.push((level, n));
            }
            if let Some(n) = node.take_child() {
                track_assert_ne!(level, 0xFFFF, ErrorKind::Other);
                self.stack.push((level + 1, n));
            }
            self.in_progress = false;
            self.label_offset = 0;
        }
        Ok(offset)
    }

    fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
        track_assert!(self.is_idle(), ErrorKind::EncoderFull);
        self.stack.push((0, item));
        Ok(())
    }

    fn is_idle(&self) -> bool {
        self.stack.is_empty()
    }

    fn requiring_bytes(&self) -> ByteCount {
        ByteCount::Unknown
    }
}

#[derive(Debug, Default)]
struct HeaderDecoder {
    inner: TupleDecoder<(U8Decoder, U8Decoder, U16beDecoder)>,
}
impl Decode for HeaderDecoder {
    type Item = Header;

    fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
        track!(self.inner.decode(buf, eos))
    }

    fn finish_decoding(&mut self) -> Result<Self::Item> {
        let item = track!(self.inner.finish_decoding())?;
        Ok(Header {
            flags: Flags::from_bits_truncate(item.0),
            label_len: item.1,
            level: item.2,
        })
    }

    fn requiring_bytes(&self) -> ByteCount {
        self.inner.requiring_bytes()
    }

    fn is_idle(&self) -> bool {
        self.inner.is_idle()
    }
}

#[derive(Debug, Default)]
struct HeaderEncoder {
    inner: TupleEncoder<(U8Encoder, U8Encoder, U16beEncoder)>,
}
impl Encode for HeaderEncoder {
    type Item = Header;

    fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
        track!(self.inner.encode(buf, eos))
    }

    fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
        let t = (item.flags.bits(), item.label_len, item.level);
        track!(self.inner.start_encoding(t))
    }

    fn is_idle(&self) -> bool {
        self.inner.is_idle()
    }

    fn requiring_bytes(&self) -> ByteCount {
        self.inner.requiring_bytes()
    }
}

#[derive(Debug)]
struct Header {
    flags: Flags,
    label_len: u8,
    level: u16,
}
impl Header {
    fn new<V>(level: u16, node: &Node<V>) -> Self {
        Header {
            flags: node.flags(),
            label_len: node.label().len() as u8,
            level,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;
    use crate::PatriciaMap;
    use bytecodec::fixnum::{U32beDecoder, U32beEncoder, U8Decoder, U8Encoder};
    use bytecodec::io::IoEncodeExt;
    use bytecodec::{Decode, EncodeExt, Eos};

    #[test]
    fn encoder_and_decoder_works() {
        let mut input = vec![(Vec::from("foo"), 1), ("bar".into(), 2), ("baz".into(), 3)];
        input.sort();

        let map: PatriciaMap<_> = input.iter().cloned().collect();
        let root = Node::from(map);

        let mut buf = Vec::new();
        let mut encoder = track_try_unwrap!(NodeEncoder::<U8Encoder>::with_item(root));
        track_try_unwrap!(encoder.encode_all(&mut buf));

        let mut decoder = NodeDecoder::new(U8Decoder::new());
        let size = track_try_unwrap!(decoder.decode(&buf, Eos::new(true)));
        assert_eq!(size, buf.len());

        let item = track_try_unwrap!(decoder.finish_decoding());
        let map = PatriciaMap::from(item);
        assert_eq!(map.len(), 3);
        assert_eq!(map.into_iter().collect::<Vec<_>>(), input);
    }

    #[test]
    fn large_encoder_and_decoder_works() {
        let mut input = (0..10000)
            .map(|i| (i.to_string().into_bytes(), i))
            .collect::<Vec<_>>();
        input.sort();

        let map: PatriciaMap<_> = input.iter().cloned().collect();
        let root = Node::from(map);

        let mut buf = Vec::new();
        let mut encoder = track_try_unwrap!(NodeEncoder::<U32beEncoder>::with_item(root));
        track_try_unwrap!(encoder.encode_all(&mut buf));

        let mut decoder = NodeDecoder::new(U32beDecoder::new());
        let size = track_try_unwrap!(decoder.decode(&buf, Eos::new(true)));
        assert_eq!(size, buf.len());

        let item = track_try_unwrap!(decoder.finish_decoding());
        let map = PatriciaMap::from(item);
        assert_eq!(map.len(), 10000);
        assert_eq!(map.into_iter().collect::<Vec<_>>(), input);
    }
}
