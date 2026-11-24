// Port of snort3 src/packet_io/trough.h 88 L (md5 7931b6efeaf3c329449e7038f68b9d59)
// + src/packet_io/trough.cc 265 L (md5 c9aa106b99f5bd4592b8a27fff81d5f8)
// @ fe29cbe (row 23d). "Trough provides access to sources (interface,
// file, etc.)" (trough.h :27): the pcap-source expander — the config
// pushes PcapReadObject entries (file-list file / space-separated list /
// directory+filter), setup() expands them into the pcap_queue, and
// get_next()/loop_count drive the replay walk while file_count counts
// every surfaced source.
//
// THE 23c CROSS-ROW face CLOSED HERE: the 23c peg/stats port's prep_counts
// (:267 cc) / reset_stats (:294 cc) seam params `trough_file_count` ride
// a caller-threaded PegCount (the 23c seam-param law — sfmod's scripted
// face NEVER moves, its twin pins the fc=0 scripted legs); the producer
// side — the ONE home of the file_count counter with the REAL bump at
// :257 — lands HERE (one-home law; the 23c witness mirror was the
// NOT-landed placeholder for exactly this home).
//
// THE C is a pure STATIC-CLASS: every member is `static` (trough.h :39-:84;
// the :84 `static std::atomic<unsigned> file_count;` face — class-static,
// honestly READ: NOT a file-static). The port rides the landed sfdaq.rs
// static-class precedent: the statics become facade FIELDS on a `Trough`
// value (no thread-unsafe statics in Rust; the caller owns one Trough =
// the one global in C; the harness + the parity twin pin the faces on ONE
// instance). get_file_count()/clear_file_count() (:48/:52) + get_queue_size()
// (:56) + get_loop_count() (:60) stay the header INLINEs (the 23c nm face
// `EXACTLY-1 Trough::file_count` rode exactly these).
//
// Deviations (each cited at KNOWN DEVIATIONS.md row 23d):
// - FatalError (:221/:224) -> Err(()) AFTER the engine emits the message:
//   the landed log home models C's never-returning FatalError as
//   LogEngine::fatal_error -> Fatal (the 23a law); the port surfaces a
//   typed Err and the caller controls flow (NEVER abort in lib code).
// - getline -> lines(): the C reads a list file line-by-line (fstream :79);
//   the port reads the file and splits on '\n' (a final newline yields no
//   extra line — the same vector the C getline loop produces: getline
//   NEVER returns a line without characters and stops at EOF-without-
//   newline exactly once with that content).
// - the std::vector iter face -> an usize cursor (pcap_queue_iter :80 ->
//   `queue_iter`): same observable has_next/get_next/loop-wrap semantics,
//   pinned by the vectors Q-legs.
// - errno (the C reads it post-fstat/getline-fail): the port carries the
//   raw OS code where the message leg prints get_error(errno) (the landed
//   utils::get_error home REUSED — never re-forked).
// - fnmatch: the helpers::directory home REUSED (the same glibc flags-0
//   subset; the two C call sites BOTH pass 0 — the law holds face-by-face;
//   NEVER re-authored here, one-home).

use std::fs;
use std::os::unix::fs::MetadataExt;

use crate::helpers::directory::{Directory, S_IFIFO, S_IFMT, S_IFREG, fnmatch};
use crate::log::messages::{Fatal, LogEngine};
use crate::utils::cfmt::Arg;
use crate::utils::util::get_error;

/// `enum SourceType` (trough.h :32-:37) — declaration-order ordinals:
/// SOURCE_FILE_LIST=0, SOURCE_LIST=1, SOURCE_DIR=2.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SourceType {
    SourceFileList = 0, // :34 — a file containing a list of sources
    SourceList = 1,     // :35 — a list of sources (eg from cmd line)
    SourceDir = 2,      // :36 — a directory of sources; often filter'd
}

/// `struct PcapReadObject` (trough.h :66-:71): type (default
/// SOURCE_FILE_LIST :68) + arg + filter.
#[derive(Clone, Debug)]
pub struct PcapReadObject {
    pub p_type: SourceType, // :68 `type = SOURCE_FILE_LIST` face
    pub arg: String,        // :69
    pub filter: String,     // :70
}

/// the cc :41 definition face: `pcap_filter = "*.*cap*"` — the built-in
/// default filter a source adopts when added (add_source :203).
pub const DEFAULT_PCAP_FILTER: &str = "*.*cap*";

/// THE Trough facade (the C pure-static class -> fields, the sfdaq.rs
/// static-class precedent; the private legs :73-:76 land as pub fns the
/// harness/twin drive — the landed flat-cite law).
pub struct Trough {
    // :78 static std::vector<PcapReadObject> pcap_object_list
    object_list: Vec<PcapReadObject>,
    // :79 static std::vector<std::string> pcap_queue
    queue: Vec<String>,
    // :80 static iter pcap_queue_iter -> usize cursor (deviation cited)
    queue_iter: usize,
    // :81 static std::string pcap_filter (the "*.*cap*" init face)
    filter: String,
    // :83 static unsigned pcap_loop_count
    loop_count: u32,
    // :84 static std::atomic<unsigned> file_count{0} -> FIELD (THE
    // one-home counter; the REAL bump lives at get_next :257)
    file_count: u32,
}

impl Default for Trough {
    /// the cc :39-:45 static-init face: empty vectors, `pcap_filter =
    /// "*.*cap*"` (:41), default-constructed iter (-> cursor 0),
    /// pcap_loop_count = 0 (:44), file_count{0} (:45).
    fn default() -> Self {
        Trough {
            object_list: Vec::new(),
            queue: Vec::new(),
            queue_iter: 0,
            filter: DEFAULT_PCAP_FILTER.to_string(), // :41
            loop_count: 0,                            // :44
            file_count: 0,                            // :45
        }
    }
}

impl Trough {
    /// :39 set_loop_count(c) — the INLINE face.
    pub fn set_loop_count(&mut self, c: u32) {
        self.loop_count = c;
    }

    /// :62 get_loop_count() — the INLINE face.
    pub fn get_loop_count(&self) -> u32 {
        self.loop_count
    }

    /// :48 get_file_count() — the INLINE face (23c seam: sfmod's
    /// `trough_file_count` param producer).
    pub fn get_file_count(&self) -> u32 {
        self.file_count
    }

    /// :52 clear_file_count() — the INLINE face (`file_count = 0`).
    pub fn clear_file_count(&mut self) {
        self.file_count = 0;
    }

    /// :56 get_queue_size() — the INLINE face (`pcap_queue.size()`).
    pub fn get_queue_size(&self) -> u32 {
        self.queue.len() as u32
    }

    /// :43 set_filter(f): if (f) pcap_filter = f; else pcap_filter.erase()
    /// (cc :208-:214 — the NONE face erases).
    pub fn set_filter(&mut self, f: Option<&str>) {
        match f {
            Some(f) => self.filter = f.to_string(),
            None => self.filter.clear(), // :213 erase()
        }
    }

    /// the filter face (inspection surface; C keeps pcap_filter private —
    /// the setup() :231 clear leg is vectors-pinned through it).
    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// :44 add_source(type, list) (cc :197-:206): PcapReadObject pro with
    /// type + arg=list + filter=pcap_filter CURRENT; emplace_back.
    pub fn add_source(&mut self, p_type: SourceType, list: &str) {
        let pro = PcapReadObject {
            p_type,
            arg: list.to_string(), // :202
            filter: self.filter.clone(), // :203 — the CURRENT filter face
        };
        self.object_list.push(pro); // :205
    }

    /// :73 add_pcaps_dir(dirname, filter) (cc :47-:67): open the
    /// Directory iterator; on error emit + false (:50-:55); collect all
    /// next() names (:59-:60), std::sort (:61), append to the queue
    /// (:63-:64). THE SORT face: the queue order from a DIR walk is
    /// sorted — the vectors pin it.
    pub fn add_pcaps_dir(&mut self, dirname: &str, filter: &str, log: &mut LogEngine) -> bool {
        let mut pcap_dir = Directory::new(dirname, Some(filter));
        // :50 `if (pcap_dir.error_on_open())` — the errno face
        if pcap_dir.error_on_open() != 0 {
            let e = pcap_dir.error_on_open(); // the C calls it twice (:50/:53)
            // :52-:53 ErrorMessage("Error getting pcaps under dir: %s: %s\n",
            // dirname, get_error(errno))
            log.error_message(
                "Error getting pcaps under dir: %s: %s\n",
                &[Arg::S(Some(dirname.into())), Arg::S(Some(get_error(e).into()))],
            );
            return false;
        }

        // :57-:60 tmp_queue += every next()
        let mut tmp_queue: Vec<String> = Vec::new();
        for name in pcap_dir.by_ref() {
            tmp_queue.push(name);
        }
        tmp_queue.sort(); // :61 std::sort (byte order == C std::string `<`)

        // :63-:64 pcap_queue.insert(end, tmp_queue...)
        self.queue.reserve(self.queue.len() + tmp_queue.len());
        self.queue.append(&mut tmp_queue);
        true
    }

    /// :74 add_pcaps_list_file(list_filename, filter) (cc :69-:121): the
    /// ifstream face (:71-:76), the getline loop (:79-:117) with the
    /// whitespace trim (:81-:84), the empty skip (:86-:87), the per-entry
    /// stat (:89-:96), DIRrecurse (:97-:104), REG + filter (:105-:109),
    /// the not-file/dir abort face (:110-:116).
    pub fn add_pcaps_list_file(
        &mut self,
        list_filename: &str,
        filter: &str,
        log: &mut LogEngine,
    ) -> bool {
        let content = match fs::read_to_string(list_filename) {
            Ok(c) => c,
            Err(e) => {
                // :72-:76 is_open() fail: get_error(errno) face
                let e = e.raw_os_error().unwrap_or(2); // the ENOENT fallback, cited
                log.error_message(
                    "Could not open pcap list file: %s: %s\n",
                    &[
                        Arg::S(Some(list_filename.into())),
                        Arg::S(Some(get_error(e).into())),
                    ],
                );
                return false;
            }
        };

        // the getline loop (deviation: lines() face); the C trims with the
        // " \x0c\n\r\t\x0b" set (:82), then skips empties (:86).
        for raw in content.lines() {
            let mut pcap_name = raw.to_string();
            // :83 erase(0, find_first_not_of(ws)) + :84 erase(find_last_not_of(ws)+1)
            pcap_name = pcap_name.trim_matches(|c: char| " \x0c\n\r\t\x0b".contains(c)).to_string();
            if pcap_name.is_empty() {
                continue; // :86-:87
            }

            // :89-:96 `if (stat(...) == -1)` -> emit + close + return false
            let md = match fs::metadata(&pcap_name) {
                Ok(md) => md,
                Err(e) => {
                    let e = e.raw_os_error().unwrap_or(2); // cited fallback
                    log.error_message(
                        "Error getting stat on pcap file: %s: %s\n",
                        &[
                            Arg::S(Some(pcap_name.as_str().into())),
                            Arg::S(Some(get_error(e).into())),
                        ],
                    );
                    return false; // :94-:95 close + false
                }
            };
            let mode = md.mode() & S_IFMT;
            if mode == crate::helpers::directory::S_IFDIR {
                // :97-:104 the DIR recurse (filter rides through)
                if !self.add_pcaps_dir(&pcap_name, filter, log) {
                    return false; // :100-:102
                }
            } else if mode == S_IFREG {
                // :105-:109 `filter.empty() || fnmatch(...) == 0` -> push
                // (the WHOLE path fnmatch'd at this site — the d_name face
                // at the Directory site lives THERE, both pinned)
                if filter.is_empty() || fnmatch(filter, &pcap_name) == 0 {
                    self.queue.push(pcap_name); // :108
                }
            } else {
                // :110-:116 the neither-face (the FIFO entry rides it —
                // vectors Q-leg; the C escapes the quotes literally)
                log.error_message(
                    "Specified entry in '%s' is not a regular file or directory: %s\n",
                    &[
                        Arg::S(Some(list_filename.into())),
                        Arg::S(Some(pcap_name.as_str().into())),
                    ],
                );
                return false; // :114-:115
            }
        }
        // :118-:120 close + true
        true
    }

    /// :75 add_pcaps_list(list) (cc :123-:166): empty -> emit + false
    /// (:125-:129); the space-split do/while (:131-:163, the npos face:
    /// last token runs to end); the "-" stdin bypass (:146); the stat
    /// guard (:148-:154 — the errno + (%d) face); the REG-or-FIFO mask
    /// (:155-:159 `!(st_mode & (S_IFREG|S_IFIFO))`); push (:162).
    pub fn add_pcaps_list(&mut self, list: &str, log: &mut LogEngine) -> bool {
        if list.is_empty() {
            log.error_message("No pcaps specified in pcap list\n", &[]); // :127
            return false;
        }

        let mut i = 0usize;
        loop {
            // :137-:144 pos = list.find(' '); tail-vs-slice face
            let (pcap_name, done) = match list[i..].find(' ') {
                Some(rel) => {
                    let pos = i + rel;
                    (list[i..pos].to_string(), pos + 1)
                }
                None => (list[i..].to_string(), usize::MAX),
            };

            if pcap_name != "-" {
                // :146-:160 the stat + REG-or-FIFO mask faces
                match fs::metadata(&pcap_name) {
                    Err(e) => {
                        let e = e.raw_os_error().unwrap_or(2); // cited
                        log.error_message(
                            "Error getting stat on file: %s: %s (%d)\n",
                            &[
                                Arg::S(Some(pcap_name.as_str().into())),
                                Arg::S(Some(get_error(e).into())),
                                Arg::I(e as i64), // the :152 (%d) face
                            ],
                        );
                        return false;
                    }
                    Ok(md) => {
                        let mode = md.mode() & S_IFMT;
                        if mode != S_IFREG && mode != S_IFIFO {
                            log.error_message(
                                "Specified pcap is not a regular file: %s\n",
                                &[Arg::S(Some(pcap_name.as_str().into()))],
                            );
                            return false;
                        }
                    }
                }
            }

            self.queue.push(pcap_name); // :162

            if done == usize::MAX {
                break; // :163 while (pos != npos)
            }
            i = done; // :143 i = ++pos
        }
        true
    }

    /// :76 get_pcaps(pol) (cc :168-:195): switch on pro.type, three
    /// private legs; any false short-circuits.
    fn get_pcaps(&mut self, pol: &[PcapReadObject], log: &mut LogEngine) -> bool {
        for pro in pol {
            match pro.p_type {
                SourceType::SourceFileList => {
                    // :174-:178
                    if !self.add_pcaps_list_file(&pro.arg, &pro.filter, log) {
                        return false;
                    }
                }
                SourceType::SourceList => {
                    // :180-:184 (no filter leg — the LIST path never filters)
                    if !self.add_pcaps_list(&pro.arg, log) {
                        return false;
                    }
                }
                SourceType::SourceDir => {
                    // :186-:190
                    if !self.add_pcaps_dir(&pro.arg, &pro.filter, log) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// :45 setup() (cc :216-:232) — the expander. THE FatalError legs
    /// (:221/:224) -> Err(Fatal) deviation (header law; the Err arm REUSES
    /// the landed log::messages Fatal home — the engine's own return type,
    /// NEVER a fresh error fork): the messages still emit through the
    /// landed engine home. On success: clear the object
    /// list (:227 — the "free pcap list" face, vectors Q-face) + set the
    /// iter head (:229); pcap_filter.clear() ALWAYS (:231).
    pub fn setup(&mut self, log: &mut LogEngine) -> Result<(), Fatal> {
        if !self.object_list.is_empty() {
            // the C re-borrows pcap_object_list (:220); the port takes the
            // list out and puts it back dead (same face, the borrow law)
            let pol = std::mem::take(&mut self.object_list);
            if !self.get_pcaps(&pol, log) {
                self.object_list = pol; // the C list survives the fail leg
                // :221 FatalError("Error getting pcaps.\n") -> Err (deviation)
                return Err(log.fatal_error("Error getting pcaps.\n", &[]));
            }
            if self.queue.is_empty() {
                self.object_list = pol;
                // :224 FatalError("No pcaps found.\n") -> Err (deviation)
                return Err(log.fatal_error("No pcaps found.\n", &[]));
            }
            self.object_list = Vec::new(); // :227 pcap_object_list.clear()
            self.queue_iter = 0; // :229 iter = cbegin()
        }
        self.filter.clear(); // :231 pcap_filter.clear()
        Ok(())
    }

    /// :64 cleanup() (cc :234-:238): pcap_queue.clear() ONLY (file_count
    /// SURVIVES the cleanup — the vectors Q-face; clear_file_count is the
    /// separate :52 face).
    pub fn cleanup(&mut self) {
        self.queue.clear(); // :237
    }

    /// :47 get_next() (cc :240-:259) — the WALK head: empty/exhausted ->
    /// nullptr; else the name (:247), ++iter (:248), and THE LOOP-WRAP arm
    /// (:251-:255 end + loop_count > 1 -> decrement + rewind head), then
    /// THE file_count++ bump (:257 — the ONE home of the counter the 23c
    /// seam reads).
    pub fn get_next(&mut self) -> Option<String> {
        if self.queue.is_empty() || self.queue_iter >= self.queue.len() {
            return None; // :244-:245
        }
        let pcap = self.queue[self.queue_iter].clone(); // :247 (owned, header law)
        self.queue_iter += 1; // :248
        if self.queue_iter == self.queue.len() && self.loop_count > 1 {
            self.loop_count -= 1; // :253
            self.queue_iter = 0; // :254
        }
        self.file_count += 1; // :257 THE bump (the pcaps producer face)
        Some(pcap)
    }

    /// :46 has_next() (cc :261-:264): !queue.empty() && iter != end.
    pub fn has_next(&self) -> bool {
        !self.queue.is_empty() && self.queue_iter < self.queue.len()
    }

    /// the OBJECT-LIST size face (inspection surface; C keeps the vector
    /// private — the setup() :227 clear leg pin rides it).
    pub fn object_list_len(&self) -> usize {
        self.object_list.len()
    }

    /// an added-source twin read (inspection surface for the harness /
    /// the twin; the C PcapReadObject vector stays private, filter face
    /// pinned by the add_source CURRENT-filter law :203).
    pub fn object_at(&self, i: usize) -> Option<&PcapReadObject> {
        self.object_list.get(i)
    }
}
