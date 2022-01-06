// use std::fs::File;
// use std::io::{self, Read, BufReader};

// use std::cmp::min;
// use std::marker::PhantomData;

// // Ideally, this would hold a `String` inside. But we need a lifetime parameter
// // here so we can return an &'a str from `peek_slice`. The alternative is to
// // give a lifetime to the `Input` trait and use it in the `peek_slice` method.
// // But that lifetime will pollute everything. Finally, the _correct_ thing is
// // for Rust to let us reference the lifetime of `self` in an associated type.
// // That requires something like https://github.com/rust-lang/rfcs/pull/1598.
// #[derive(Debug)]
// pub struct StringFile<'s> {
//     buffer: Vec<u8>,
//     consumed: usize,
//     pos: usize,
//     reader: BufReader<File>,
//     _string: PhantomData<&'s str>
// }

// impl<'s> StringFile<'s> {
//     #[inline(always)]
//     pub fn open(path: &str) -> io::Result<StringFile<'s>> {
//         Ok(StringFile::new(File::open(path)?, 1024))
//     }

//     #[inline(always)]
//     pub fn open_with_cap(path: &str, cap: usize) -> io::Result<StringFile<'s>> {
//         Ok(StringFile::new(File::open(path)?, cap))
//     }

//     #[inline(always)]
//     pub fn new(file: File, cap: usize) -> StringFile<'s> {
//         StringFile {
//             buffer: vec![0; cap],
//             consumed: 0,
//             pos: 0,
//             reader: BufReader::new(file),
//             _string: PhantomData
//         }
//     }

//     #[inline(always)]
//     pub fn available(&self) -> usize {
//         self.pos - self.consumed
//     }

//     fn read_into_peek(&mut self, num: usize) -> io::Result<usize> {
//         if self.available() >= num {
//             return Ok(num);
//         }

//         let needed = num - self.available();
//         let to_read = min(self.buffer.len() - self.pos, needed);
//         let (i, j) = (self.pos, self.pos + to_read);
//         let read = self.reader.read(&mut self.buffer[i..j])?;

//         self.pos += read;
//         Ok(self.available())
//     }

//     // Panics if at least `num` aren't available.
//     #[inline(always)]
//     fn peek_bytes(&self, num: usize) -> &[u8] {
//         &self.buffer[self.consumed..(self.consumed + num)]
//     }

//     fn consume(&mut self, num: usize) {
//         if self.pos < num {
//             let left = (num - self.pos) as u64;
//             self.consumed = 0;
//             self.pos = 0;
//             // TOOD: Probably don't ignore this?
//             let _ = io::copy(&mut self.reader.by_ref().take(left), &mut io::sink());
//         } else {
//             self.consumed += num;
//         }
//     }

//     #[inline]
//     fn peek_char(&mut self) -> Option<char> {
//         let available = match self.read_into_peek(4) {
//             Ok(n) => n,
//             Err(_) => return None
//         };

//         let bytes = self.peek_bytes(available);
//         let string = match ::std::str::from_utf8(bytes) {
//             Ok(string) => string,
//             Err(e) => match ::std::str::from_utf8(&bytes[..e.valid_up_to()]) {
//                 Ok(string) => string,
//                 Err(_) => return None
//             }
//         };

//         string.chars().next()
//     }
// }

// impl<'s> Input for StringFile<'s> {
//     type Token = char;
//     type InSlice = &'s str;
//     type Slice = &'s str;
//     type Many = String;
//     type Context = &'s str;

//     // If we took Self::Token here, we'd know the length of the character.
//     #[inline(always)]
//     fn peek(&mut self) -> Option<Self::Token> {
//         self.peek_char()
//     }

//     fn take_many<F: FnMut(&Self::Token) -> bool>(&mut self, mut cond: F) -> Self::Many {
//         let mut result = String::new();
//         while let Some(c) = self.peek_char() {
//             if cond(&c) {
//                 result.push(c);
//                 self.consume(c.len_utf8());
//             } else {
//                 break;
//             }
//         }

//         result
//     }

//     fn skip_many<F: FnMut(&Self::Token) -> bool>(&mut self, mut cond: F) -> usize {
//         let mut taken = 0;
//         while let Some(c) = self.peek_char() {
//             if cond(&c) {
//                 self.consume(c.len_utf8());
//                 taken += 1;
//             } else {
//                 return taken;
//             }
//         }

//         taken
//     }

//     fn peek_slice(&mut self, slice: Self::InSlice) -> Option<Self::Slice> {
//         let available = match self.read_into_peek(slice.len()) {
//             Ok(n) => n,
//             Err(_) => return None
//         };

//         let bytes = self.peek_bytes(available);
//         let string = match ::std::str::from_utf8(bytes) {
//             Ok(string) => string,
//             Err(e) => match ::std::str::from_utf8(&bytes[..e.valid_up_to()]) {
//                 Ok(string) => string,
//                 Err(_) => return None
//             }
//         };

//         match string == slice {
//             true => Some(slice),
//             false => None
//         }
//     }

//     #[inline(always)]
//     fn advance(&mut self, count: usize) {
//         self.consume(count);
//     }

//     #[inline(always)]
//     fn is_empty(&mut self) -> bool {
//         match self.read_into_peek(1) {
//             Ok(0) | Err(_) => true,
//             Ok(_) => false,
//         }
//     }
// }

