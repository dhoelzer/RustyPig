// Port of snort3 src/helpers/directory.h 49 L (md5 f7eac140e21c6cecd14ba6e00d546ea4)
// + src/helpers/directory.cc 113 L (md5 e0e4af65fd338c1b9add303142aa36cc)
// @ fe29cbe (row 23d). "simple directory traversal" (directory.h :23): a
// recursive-descent file iterator — opendir the root, walk readdir, descend
// into each subdirectory in place (the sub iterator becomes the walk head),
// and surface only regular files matching an optional fnmatch(3) filter.
//
// The C pairs' ZERO-TEST face measured at the row: directory.{cc,h} +
// trough.{cc,h} carry EXACTLY-0 TEST_CASE/UNIT_TEST faces (the quad grep,
// 0/0/0/0 — re-verified by the row harness every build) and the
// helpers/test CMake carries NO directory suite (add_cpputest EXACTLY-4,
// 'directory' grep-0) => the row stays a ZERO-gate pick.
//
// Deviations (each cited at KNOWN DEVIATIONS.md row 23d):
// - readdir stream -> Vec snapshot: C holds an open DIR* and interleaves
//   readdir with recursion; the port materializes per-directory entries
//   once when the handle opens. The observable order is the SAME readdir
//   order (readdir returns the whole directory's stream; the C walk never
//   mutates the directory mid-walk — the harness trees are built before
//   the walk starts). rewind() re-reads (C rewinddir, directory.cc :61).
// - next() returns an owned String, not the C `const char*` into the
//   mutable `path` buffer (directory.cc :109); the C iterator INVALIDATES
//   the previous pointer on the next call — the port keeps the same
//   `path` field mutations (`path.erase(len)` face) for the string VALUES
//   and hands out clones; no caller in the C tree reads two names at once.
// - stat(2) follows symlinks in C (directory.cc :93): the port rides
//   fs::metadata (follows), NEVER DirEntry::metadata (lstat face) — cited.
// - fnmatch(PATTERN, NAME, 0) with glibc flags=0 (directory.cc :105): a
//   byte-exact SUBSET port of the glibc face the two call sites ride
//   ('*'/'?' span '/', '[...]' classes with [!..] negation + ranges,
//   '\' escapes; unterminated '[' is a literal; the FNM_PATHNAME/CASEFOLD
//   flags are NEVER reachable here since both callers pass 0). The
//   glibc KBA semantics ride the FACE-A vectors face (pass_slash/nomatch/
//   class pins, the row harness FACE-A vectors).
// - errno: `error_on_open()` (directory.h :34) returns the C errno value
//   after opendir/stat failure (ENOENT=2 / ENOTDIR=20 faces pinned by the
//   FACE-A ERRS line); a Rust io error without an OS code falls back to 2,
//   cited (POSIX read_dir failures always carry one).

use std::fs;
use std::os::unix::fs::MetadataExt;

/// limits.h PATH_MAX (glibc face 4096 — FACE-A LIMITS pin). The C walk
/// refuses a path strictly OVER PATH_MAX-1 (directory.cc :93).
pub const PATH_MAX: usize = 4096;

// bits/stat.h file-type masks (glibc octal faces, FACE-A MODES pin —
// S_IFMT 0170000 = 61440, S_IFDIR 0040000 = 16384, S_IFREG 0100000 =
// 32768, S_IFIFO 0010000 = 4096): the S_ISDIR/S_ISREG macros (directory.cc
// :96/:101) and the trough.cc sibling ride these exact bit tests.
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFIFO: u32 = 0o010000;

/// fnmatch(3) return values (fnmatch.h glibc face): 0 == match,
/// FNM_NOMATCH == 1 (the flags-0 call sites compare `!= 0`, both files).
pub const FNM_NOMATCH: i32 = 1;

/// fnmatch(PATTERN, NAME, 0) — the glibc flags-0 subset (see the header
/// deviation law). Bytes throughout (the C walks byte strings; bracket
/// ranges are C-locale byte comparisons). 0 == match, FNM_NOMATCH otherwise.
/// KBA: the star-backtrack two-pointer walk; '*' and '?' span '/' (no
/// FNM_PATHNAME), '\' escapes unless it is the trailing byte (then it is
/// literal), an unterminated '[' is a literal '[' — every leg FACE-A-pinned
/// or twin-pinned against glibc through the harness vectors.
pub fn fnmatch(pattern: &str, name: &str) -> i32 {
    fn_match(pattern.as_bytes(), name.as_bytes())
}

fn fn_class(pattern: &[u8], bracket: usize, ch: u8) -> Option<(usize, bool)> {
    // bracket points at '['; returns (index PAST the class, matched).
    let mut i = bracket + 1;
    if i >= pattern.len() {
        return None; // lone '[' -> literal (glibc: no closing ']' face)
    }
    let negate = pattern[i] == b'!';
    if negate {
        i += 1;
    }
    let mut first = true; // a ']' right after '[' / '[!' is a literal member
    let mut matched = false;
    loop {
        if i >= pattern.len() {
            return None; // unterminated -> literal
        }
        if pattern[i] == b']' && !first {
            return Some((i + 1, matched != negate));
        }
        first = false;
        let mut lo = pattern[i];
        if lo == b'\\' && i + 1 < pattern.len() {
            i += 1;
            lo = pattern[i];
        }
        i += 1;
        if i + 1 < pattern.len() && pattern[i] == b'-' && pattern[i + 1] != b']' {
            i += 1;
            let mut hi = pattern[i];
            if hi == b'\\' && i + 1 < pattern.len() {
                i += 1;
                hi = pattern[i];
            }
            i += 1;
            if lo as i32 <= ch as i32 && (ch as i32) <= (hi as i32) {
                matched = true;
            }
        } else if lo == ch {
            matched = true;
        }
    }
}

fn fn_match(pattern: &[u8], text: &[u8]) -> i32 {
    let mut p = 0usize; // pattern cursor
    let mut t = 0usize; // text cursor
    let mut star_p: usize = usize::MAX; // last '*' (usize::MAX == none)
    let mut star_t = 0usize; // text position to retry from
    while t < text.len() {
        if p < pattern.len() {
            match pattern[p] {
                b'?' => {
                    p += 1;
                    t += 1;
                    continue;
                }
                b'*' => {
                    star_p = p;
                    star_t = t;
                    p += 1;
                    continue;
                }
                b'[' => {
                    if let Some((end, m)) = fn_class(pattern, p, text[t]) {
                        if m {
                            p = end;
                            t += 1;
                            continue;
                        }
                    } else if pattern[p] == text[t] {
                        // unterminated '[' literal face
                        p += 1;
                        t += 1;
                        continue;
                    }
                }
                b'\\' if p + 1 < pattern.len() => {
                    if pattern[p + 1] != text[t] {
                        // fall into the mismatch/backtrack leg below
                    } else {
                        p += 2;
                        t += 1;
                        continue;
                    }
                }
                c if c == text[t] => {
                    p += 1;
                    t += 1;
                    continue;
                }
                _ => {}
            }
        }
        // mismatch: backtrack to the last '*' (glibc wildcard retry face)
        if star_p != usize::MAX {
            star_t += 1;
            t = star_t;
            p = star_p + 1;
            continue;
        }
        return FNM_NOMATCH;
    }
    // text exhausted: only '*' may remain ('?' / class / literal need a char)
    while p < pattern.len() {
        if pattern[p] != b'*' {
            if pattern[p] == b'[' && fn_class(pattern, p, 0).is_none() {
                return FNM_NOMATCH; // a literal '[' never matches empty tail
            }
            return FNM_NOMATCH;
        }
        p += 1;
    }
    0
}

/// `class Directory` (directory.h :28-:46): the recursive walk iterator.
/// The C private members (:39-:45) land as fields (the file/member ->
/// field law): `dir` (the DIR* handle -> the entry snapshot + cursor, the
/// header deviation), `root`, `filter`, `path`, `len`, `sub`, `error`.
pub struct Directory {
    root: String,
    filter: String,
    path: String,
    len: usize,          // :43 — strlen(root) (directory.cc :37)
    sub: Option<Box<Directory>>, // :44 — the in-place recursion head
    error: i32,          // :45 — the opendir errno face (:41)
    entries: Vec<fs::DirEntry>, // the DIR* stream face (deviation cited)
    cursor: usize,       // the readdir position face (deviation cited)
}

impl Directory {
    /// Directory::Directory(s, f = nullptr) (directory.cc :33-:42):
    /// opendir + root/len/path/filter/sub/error init, EXACT order.
    pub fn new(s: &str, f: Option<&str>) -> Self {
        // dir = opendir(s); root = s; len = strlen(s); path = root;
        // sub = nullptr; filter = f ? f : ""; error = dir ? 0 : errno;
        let mut error = 0;
        let entries = match fs::read_dir(s) {
            Ok(rd) => rd.filter_map(Result::ok).collect(),
            Err(e) => {
                error = e.raw_os_error().unwrap_or(2); // the ENOENT fallback, cited
                Vec::new()
            }
        };
        Directory {
            root: s.to_string(),
            filter: f.unwrap_or("").to_string(),
            path: s.to_string(), // path = root (C copies the root face)
            len: s.len(),
            sub: None,
            error,
            entries,
            cursor: 0,
        }
    }

    /// :34 error_on_open() -> the stored opendir errno (directory.cc :53-:56).
    pub fn error_on_open(&self) -> i32 {
        self.error
    }

    /// :35 rewind() (directory.cc :58-:65): rewinddir the handle AND
    /// delete the live sub — the port re-reads the stream and drops sub.
    pub fn rewind(&mut self) {
        if self.error == 0 {
            // dir != nullptr face (:60): rewinddir == re-open the stream
            if let Ok(rd) = fs::read_dir(&self.root) {
                self.entries = rd.filter_map(Result::ok).collect();
            } else {
                self.entries.clear();
            }
            self.cursor = 0;
        }
        self.sub = None; // :63-:64 if (sub) delete sub (the drop face)
    }

    /// :36 next() (directory.cc :67-:112) — the HEART. Drain the sub head
    /// first (:69-:78, delete-on-exhaust); then stream entries:
    /// :86 the strncmp(".",1) dot skip (skips '.'/'..' AND every dot file),
    /// :89-:91 the path rebuild (erase(len) + '/' + name), :93 the
    /// PATH_MAX-1 / stat guard, :96-:100 the S_ISDIR descend (new sub +
    /// recursive next()), :101 the not-regular skip, :105 the fnmatch
    /// filter (:109 the return path.c_str()).
    fn next_impl(&mut self) -> Option<String> {
        if let Some(sub) = self.sub.as_mut()
            && let Some(s) = sub.next()
        {
            return Some(s); // :73-:74
        }
        self.sub = None; // :76-:77 delete sub; sub = nullptr

        while self.cursor < self.entries.len() {
            // the snapshot face (deviation): the entry name is read by
            // INDEX so no borrow of self.entries rides self.path/self.sub
            // mutation (the C DIR* stream carries the same non-aliasing
            // property per readdir-call).
            let name = self.entries[self.cursor].file_name();
            self.cursor += 1;
            let name_bytes = name.as_encoded_bytes().to_vec();

            if name_bytes.first() == Some(&b'.') {
                continue; // :86 !strncmp(de->d_name, ".", 1)
            }
            let name_str = String::from_utf8_lossy(&name_bytes).into_owned();

            // :89-:91 path.erase(len); path += "/"; path += d_name (the
            // literal erase-to-len face — `len` = strlen(root), :37/:43)
            self.path.truncate(self.len);
            self.path.push('/');
            self.path.push_str(&name_str); // UTF-8 face cited

            let md = match fs::metadata(&self.path) {
                // :93 path.size() > PATH_MAX - 1 || stat(...)  -> continue
                _ if self.path.len() > PATH_MAX - 1 => None,
                Err(_) => None,
                Ok(md) => Some(md),
            };
            let md = match md {
                Some(md) => md,
                None => continue,
            };

            let mode = md.mode();
            if mode & S_IFMT == S_IFDIR {
                // :98-:99 sub = new Directory(path.c_str(), filter.c_str());
                //          return next();  (re-enter on SELF, the descent face)
                self.sub = Some(Box::new(Directory::new(&self.path, Some(&self.filter))));
                return self.next_impl();
            } else if mode & S_IFMT != S_IFREG {
                continue; // :101-:104 not regular (the FIFO skip face, vectors-pinned)
            } else if !self.filter.is_empty() && fnmatch(&self.filter, &name_str) != 0 {
                continue; // :105-:108 (the returned path face, deviation cited)
            }
            return Some(self.path.clone()); // :109
        }
        None // :111
    }

    /// the root face (test/inspection surface; the C keeps root private).
    pub fn root(&self) -> &str {
        &self.root
    }

    /// the filter face (test/inspection surface; the C keeps filter private).
    pub fn filter(&self) -> &str {
        &self.filter
    }
}

/// DIRECTORY's C dir.Next()-style cursor lands through BOTH spellings
/// (23d): the literal `next()` inherent face above (directory.cc :67 the
/// name EXACT) and the std Iterator adapter below (the clippy-clean law
/// — the C++ dir::next() idiom IS an iterator; the port REUSES std's home
/// rather than shipping an inherent-only confusion face).
impl Iterator for Directory {
    type Item = String;
    fn next(&mut self) -> Option<String> {
        Directory::next_impl(self)
    }
}
