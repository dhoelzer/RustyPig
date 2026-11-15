// Port of snort3 log/obfuscator.{h,cc}.
//
// Original: obfuscator.h author Victor Roemer <viroemer@cisco.com>.
//
// C uses std::set<ObfuscatorBlock, sort-by-offset> + unordered_map of
// buffer names + two iterators (cur_buf, it). Rust model: BTreeMap keyed
// by offset standing for the std::set (same offset-order iteration and
// same offset-only identity: C's set emplace dedupes on the comparator,
// and BlockCompare orders by offset alone). HashMap<String, BTreeMap>
// stands for buffer_blocks. The C iterator `it` becomes a position
// cursor re-walked on first()/next() (see KNOWN DEVIATIONS.md).

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObfuscatorBlock {
    pub offset: u32,
    pub length: usize,
}

pub const MASK_CHAR: char = 'X';

pub struct Obfuscator {
    // buffer name -> (offset-ordered blocks)
    buffer_blocks: HashMap<String, BTreeMap<u32, usize>>,
    // C cur_buf: points at the active buffer entry; None stands for
    // buffer_blocks.begin()/end() sentinel state at construction.
    cur_buf: Option<String>,
    // C `it`: index into the sorted block list (usize::MAX == end())
    it: usize,
}

impl Default for Obfuscator {
    fn default() -> Self {
        Self::new()
    }
}

impl Obfuscator {
    pub fn new() -> Self {
        // C ctor: cur_buf = buffer_blocks.begin() -- with an empty map,
        // begin() == end(); every accessor guards on that (cur_buf ==
        // end() -> set_buffer("") in push; empty checks in first/next).
        Obfuscator {
            buffer_blocks: HashMap::new(),
            cur_buf: None,
            it: usize::MAX, // end()
        }
    }

    pub fn push(&mut self, offset: u32, length: usize) {
        // C: if cur_buf == end() then set_buffer("")
        if self.cur_buf.is_none() {
            self.set_buffer("");
        }
        let name = self.cur_buf.clone().unwrap();
        let set = self.buffer_blocks.get_mut(&name).unwrap();

        // C emplace + replace-if-longer on exact-offset collision
        match set.get(&offset) {
            None => {
                set.insert(offset, length);
            }
            Some(&old_len) => {
                if length > old_len {
                    set.insert(offset, length);
                }
            }
        }
    }

    pub fn select_buffer(&mut self, buf_key: &str) -> bool {
        if !self.buffer_blocks.contains_key(buf_key) {
            return false;
        }
        self.cur_buf = Some(buf_key.to_string());
        self.it = usize::MAX; // end()
        true
    }

    pub fn set_buffer(&mut self, buf_key: &str) {
        // C: emplace(key, ObSet()).first (null key -> early return; Rust
        // has no null strs, callers pass concrete names)
        self.buffer_blocks
            .entry(buf_key.to_string())
            .or_default();
        self.cur_buf = Some(buf_key.to_string());
        self.it = usize::MAX; // end()
    }

    /// iteration in offset order (C begin()/end() over cur_buf->second)
    pub fn blocks(&self) -> Vec<ObfuscatorBlock> {
        match &self.cur_buf {
            None => Vec::new(),
            Some(name) => self
                .buffer_blocks
                .get(name)
                .map(|m| {
                    m.iter()
                        .map(|(&offset, &length)| ObfuscatorBlock { offset, length })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    pub fn first(&mut self, b: &mut ObfuscatorBlock) -> bool {
        if self.buffer_blocks.is_empty() {
            return false;
        }
        // C deref'd cur_buf unconditionally after the map-empty check;
        // None here implies an empty map (the only way to hold None is a
        // default-constructed Obfuscator), so the guard is equivalent.
        let blocks = self.blocks();
        if blocks.is_empty() {
            return false;
        }
        self.it = 0;
        *b = blocks[0];
        !blocks.is_empty()
    }

    pub fn next(&mut self, b: &mut ObfuscatorBlock) -> bool {
        if self.buffer_blocks.is_empty() {
            return false;
        }
        let blocks = self.blocks();
        if blocks.is_empty() {
            return false;
        }
        if self.it == usize::MAX {
            return false; // it == end()
        }
        self.it += 1;
        if self.it >= blocks.len() {
            return false; // ++it == end()
        }
        *b = blocks[self.it];
        true
    }

    pub fn mask_char() -> char {
        MASK_CHAR
    }
}
