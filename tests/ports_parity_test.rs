//! Ground-truth parity: replays each case string from the C++ harness output
//! (tools/cpp_harness/vectors.txt, generated from the ORIGINAL snort3 ports/
//! parser sources) through the Rust port and asserts identical items,
//! port_count, has_any, is_pure_not, has_port(80), name, hash and errflag.
use snort3::parser::parse_ports::*;
use snort3::ports::port_var_table::PortVarTable;

#[derive(Debug)]
struct Case {
    input: String,
    items: Vec<(bool, u16, u16)>,
    nc: i64,
    has_any: i64,
    pure_not: i64,
    hp80: i64,
    name: String,
    hash: u64,
    err: i32,
}

fn parse_items(line: &str) -> Vec<(bool, u16, u16)> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    let mut k = 0;
    while k < b.len() {
        if b[k] == b'[' && k + 1 < b.len() {
            let end = k + 1 + b[k + 1..].iter().position(|&c| c == b']').unwrap_or(0);
            let inner = &line[k + 1..end];
            let neg = inner.starts_with('!');
            let rest = inner.trim_start_matches('!');
            if let Some((a, hh)) = rest.split_once(':') {
                if let (Ok(a), Ok(hh)) = (a.parse(), hh.parse()) {
                    out.push((neg, a, hh));
                }
            }
            k = end + 1;
        } else {
            k += 1;
        }
    }
    out
}

fn field(d: &str, key: &str) -> Option<i64> {
    let p = d.find(&format!("{key}="))? + key.len() + 1;
    d[p..].split_whitespace().next().unwrap_or("0").parse().ok()
}

fn parse_vectors(path: &str) -> Vec<Case> {
    let txt = std::fs::read_to_string(path)
        .expect("run tools/cpp_harness/build.sh && ./harness > vectors.txt first");
    let lines: Vec<&str> = txt.lines().collect();
    let mut cases = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if !l.starts_with('<') {
            i += 1;
            continue;
        }
        // <INPUT>: items | fields   -- or --  <INPUT>: NULL
        // (inputs never contain '>', so the first ">: " is the separator)
        let label_end = l.find(">: ").expect("no '>:' separator");
        let input = l[1..label_end].to_string();

        // err line follows (either immediately at i+1, or for ok-cases the
        // vector prints  err line then optional dup line)
        let err_src = if l.contains("err=") {
            l
        } else if i + 1 < lines.len() && lines[i + 1].contains("err=") {
            lines[i + 1]
        } else {
            i += 1;
            continue; // var-flow lines handled by dedicated tests
        };
        let err: i32 = err_src[err_src.find("err=").unwrap() + 4..]
            .split(':')
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let dup_line = if i + 2 < lines.len() && lines[i + 2].starts_with("dup:") {
            Some(lines[i + 2])
        } else {
            None
        };
        let data_full = dup_line.unwrap_or(l);
        // items begin only after the "<input>:" label; the input itself may
        // contain brackets (e.g. <[80]>) which must not be scanned
        let sep = data_full.rfind(": ").expect("no label separator");
        let data = &data_full[sep..];
        cases.push(Case {
            input,
            items: parse_items(data),
            nc: field(data, "nc").unwrap_or(-999),
            has_any: field(data, "cnt_any").unwrap_or(-999),
            pure_not: field(data, "pure_not").unwrap_or(-999),
            hp80: field(data, "hp80").unwrap_or(-999),
            name: {
                let p = data.find("name=");
                match p {
                    Some(p) => data[p + 5..].split_whitespace().next().unwrap_or("").to_string(),
                    None => "NULL".to_string(),
                }
            },
            hash: field(data, "h").unwrap_or(u32::MAX as i64) as u64,
            err,
        });
        i += 2 + if dup_line.is_some() { 1 } else { 0 };
    }
    cases
}

#[test]
fn parity_against_cpp_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/cpp_harness/vectors.txt");
    let cases = parse_vectors(path);
    assert!(cases.len() >= 50, "expected many parsed cases, got {}", cases.len());

    let mut ok_cases = 0;
    let mut err_cases = 0;
    for c in &cases {
        let r = port_object_parse_string(None, None, &c.input, false, false);
        match r {
            Ok(mut po) => {
                assert_eq!(c.err, 0, "input {:?}: Rust ok but C err={}", c.input, c.err);
                let got: Vec<(bool, u16, u16)> =
                    po.items.iter().map(|i| (i.negate, i.lport, i.hport)).collect();
                assert_eq!(got, c.items, "items mismatch for {:?}", c.input);
                assert_eq!(po.port_count() as i64, c.nc, "nc mismatch for {:?}", c.input);
                assert_eq!(po.has_any() as i64, c.has_any, "has_any mismatch for {:?}", c.input);
                assert_eq!(po.is_pure_not() as i64, c.pure_not, "pure_not mismatch for {:?}", c.input);
                assert_eq!(po.has_port(80) as i64, c.hp80, "has_port(80) mismatch for {:?}", c.input);
                assert_eq!(po.name.as_deref(), Some(c.name.as_str()), "name mismatch for {:?}", c.input);
                assert_eq!(po.hash(1000, 65536, 7) as u64, c.hash, "hash mismatch for {:?}", c.input);
                ok_cases += 1;
            }
            Err((e, _)) => {
                assert_eq!(e, c.err, "err mismatch for {:?}: rust={} c={}", c.input, e, c.err);
                err_cases += 1;
            }
        }
    }
    assert!(ok_cases >= 35 && err_cases >= 12, "ok={ok_cases} err={err_cases}");
    println!("parity: {ok_cases} ok-cases, {err_cases} error-cases replayed from C++ vectors");
}

#[test]
fn parity_var_flow() {
    let mut pvt = PortVarTable::create();
    let mut po = port_object_parse_string(Some(&mut pvt), None, "HTTP_PORTS 80,443", true, false).unwrap();
    assert_eq!(po.name.as_deref(), Some("HTTP_PORTS"));
    assert_eq!(
        po.items.iter().map(|i| (i.negate, i.lport, i.hport)).collect::<Vec<_>>(),
        vec![(false, 80, 80), (false, 443, 443)]
    );
    assert_eq!(po.port_count(), 2);
    assert_eq!(po.hash(1000, 65536, 7), 12255238); // C++ var-def h=
    // register as parse_port_var does (PortVarTableAdd), then reference
    pvt.add(po.dup_ports());
    let mut po2 = port_object_parse_string(Some(&mut pvt), None, "$HTTP_PORTS,99", false, false).unwrap();
    assert_eq!(
        po2.items.iter().map(|i| (i.negate, i.lport, i.hport)).collect::<Vec<_>>(),
        vec![(false, 80, 80), (false, 99, 99), (false, 443, 443)]
    );
    assert_eq!(po2.hash(1000, 65536, 7), 12255238); // C++ var-ref h=
    let e = port_object_parse_string(Some(&mut pvt), None, "$NOPE", false, false).unwrap_err();
    assert_eq!(e.0, POPERR_BAD_VARIABLE);
}

#[test]
fn parity_remove_ports() {
    let a = port_object_parse_string(None, None, "80:90", false, false).unwrap();
    let b = port_object_parse_string(None, None, "85:86", false, false).unwrap();
    let mut a = a;
    a.remove_ports(&b);
    // C++ sub: [80:84] [87:90]
    assert_eq!(
        a.items.iter().map(|i| (i.negate, i.lport, i.hport)).collect::<Vec<_>>(),
        vec![(false, 80, 84), (false, 87, 90)]
    );
    assert_eq!(a.port_count(), 9);
    assert_eq!(a.hash(1000, 65536, 7), 5898247);
}
