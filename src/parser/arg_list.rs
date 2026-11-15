// Port of snort3 parser/arg_list.{h,cc}: CLI argv splitter used by
// parse_command_line. Quirks preserved verbatim from get_arg():
//   * the documented FIXIT-L: "-n -4" does NOT feed -4 as -n's value; the
//     pending-key branch rolls back idx and yields empty val instead;
//   * "--" leaves an EMPTY pending key (truthy pointer to the NUL in C), so
//     the flush emits key="" val="";
//   * a bare "-" is pending key "-";
//   * short option with attached value: key is the single char, val the
//     remainder (buf.assign(s,1) quirk: only one char ever lands in buf);
//   * "--long=val=ue" splits at the FIRST '='.
//   * argv[0] occupies idx 0; scanning starts at ++idx => idx 1.

#[derive(Debug, Clone)]
pub struct ArgList {
    argv: Vec<Vec<u8>>,
    argc: usize,
    idx: usize,
    arg: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl ArgList {
    pub fn new<S: AsRef<[u8]>>(v: &[S]) -> Self {
        ArgList {
            argv: v.iter().map(|s| s.as_ref().to_vec()).collect(),
            argc: v.len(),
            idx: 0,
            arg: None,
            buf: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.idx = 0;
        self.arg = None;
    }

    /// Returns Some((key, val)); empty key/val represent the C "" sentinel.
    pub fn get_arg(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        loop {
            self.idx += 1;
            if self.idx >= self.argc {
                break;
            }
            let s = self.argv[self.idx].clone();

            if let Some(key) = self.arg.take() {
                let val = if s.first().copied() != Some(b'-') {
                    s
                } else {
                    self.idx -= 1;
                    Vec::new()
                };
                return Some((key, val));
            }
            if s.first().copied() != Some(b'-') {
                return Some((Vec::new(), s));
            }
            // C reads s[1] after seeing s[0]=='-'; for s="-" that is the NUL.
            let second = s.get(1).copied();
            if second != Some(b'-') {
                let t = &s[1..];
                if t.len() > 1 {
                    self.buf = t[..1].to_vec();
                    let key = self.buf.clone();
                    return Some((key, t[1..].to_vec()));
                } else if !t.is_empty() {
                    self.arg = Some(t.to_vec());
                } else {
                    self.arg = Some(b"-".to_vec());
                }
            } else {
                let t = &s[2..];
                match t.iter().position(|&c| c == b'=') {
                    Some(eq) => {
                        self.buf = t[..eq].to_vec();
                        let key = self.buf.clone();
                        return Some((key, t[eq + 1..].to_vec()));
                    }
                    None => self.arg = Some(t.to_vec()),
                }
            }
        }
        if let Some(key) = self.arg.take() {
            return Some((key, Vec::new()));
        }
        None
    }

    /// C dump() printed argv to stdout; returns the same lines.
    pub fn dump(&self) -> String {
        let mut out = String::new();
        for (i, a) in self.argv.iter().enumerate() {
            out.push_str(&format!(
                "argv[{}]='{}'\n",
                i,
                String::from_utf8_lossy(a)
            ));
        }
        out
    }
}
