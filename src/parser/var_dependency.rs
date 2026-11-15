// Port of snort3 src/parser/var_dependency.{h,cc}.
//
// C keeps two file-static std::list<WeakVariable*> (weak_nets, weak_ports)
// plus bool resolving_nets / resolving_ports. The port puts these in the
// VarEngine (vars layer) and this module supplies the walk machinery over a
// &mut slice + a context reference — Rust can't alias the engine AND the
// list, so the resolve_nets/resolve_ports wrappers in vars.rs hand resolve()
// a split borrow (a plain C mirror is impossible with C's globals-in-
// callback model; see KNOWN DEVIATIONS). Semantics reproduced 1:1, pinned
// by tools/vars_harness vectors:
//   * extract_variable_names scans for '$', grabs [A-Za-z0-9_]+ after it,
//     then `begin = end - 1` (the for-loop's ++begin lands at end); a '$'
//     with no name chars still pushes an empty name,
//   * find_over_table: per extracted reference, first entry with
//     case-SENSITIVE name equality that is not yet visited,
//   * set_variable marks a dependency visited BEFORE recursing (C discards
//     the recursive bool — an abort longjmps out anyway), and marks
//     is_resolved BEFORE invoking the parse callback — so a callback that
//     aborts leaves a burned entry the next pass skips,
//   * resolve() EARLY-RETURNS (Ok) on the first false callback (the C
//     `return`); the resolve_nets/resolve_ports wrappers in vars.rs still
//     clear the list + reset the flag in that case (pinned: RESOLVENETS —
//     NETBAD never reaches its callback, yet the next resolve_nets ran on
//     an empty list),
//   * an uncaught ParseAbort longjmps past the clear AND the flag reset:
//     list stuck uncleaned with burned is_resolved flags, resolving flag
//     stuck TRUE (RESOLVE abort=1 resolving=1; RESOLVE2 then finishes
//     silently because every entry is already is_resolved; RESOLVE3
//     re-aborts after a fresh push). vars.rs wrappers reproduce that,
//   * `for (auto var : vars)` walks the entries present on entry: an entry
//     pushed during the walk is not visited this pass — structurally
//     enforced here, since the &mut slice borrow makes same-list pushes
//     during the walk impossible to express.
#![allow(dead_code)]

use super::messages::ParseAbort;

#[derive(Clone, Debug)]
pub struct WeakVariable {
    pub var_name: String,
    pub value: String,
    pub is_resolved: bool,
    pub is_visited: bool,
}

impl WeakVariable {
    /// WeakVariable(_var_name, _value): flags false.
    pub fn new(var_name: &str, value: &str) -> Self {
        WeakVariable {
            var_name: var_name.to_string(),
            value: value.to_string(),
            is_resolved: false,
            is_visited: false,
        }
    }
}

/// typedef bool (*parse_callback)(const char*, const char*): generic over
/// the parse context (VarEngine at the vars layer).
pub type ParseCallback<Ctx> =
    fn(ctx: &mut Ctx, name: &str, value: &str) -> Result<bool, ParseAbort>;

/// std::list<std::string> extract_variable_names(const char* input).
pub fn extract_variable_names(input: &str) -> Vec<String> {
    let b = input.as_bytes();
    let mut names = Vec::new();
    let mut begin = 0usize;
    while begin < b.len() {
        if b[begin] != b'$' {
            begin += 1;
            continue;
        }
        let mut end = begin + 1;
        while end < b.len() && ((b[end] as char).is_ascii_alphanumeric() || b[end] == b'_') {
            end += 1;
        }
        // std::string variable(input + begin + 1, end - begin - 1)
        names.push(input[begin + 1..end].to_string());
        begin = end; // C: begin = end - 1, then the for-loop's ++begin
    }
    names
}

/// std::list<WeakVariable*> find_over_table(var, vars): indices of matches.
pub fn find_over_table(var: &WeakVariable, vars: &[WeakVariable]) -> Vec<usize> {
    let mut res = Vec::new();
    for name in extract_variable_names(&var.value) {
        for (i, v) in vars.iter().enumerate() {
            if !v.is_visited && v.var_name == name {
                res.push(i);
                break;
            }
        }
    }
    res
}

/// bool set_variable(var, vars, parse_variable), addressed by index.
pub fn set_variable<Ctx>(
    idx: usize,
    vars: &mut [WeakVariable],
    ctx: &mut Ctx,
    cb: ParseCallback<Ctx>,
) -> Result<bool, ParseAbort> {
    let found = find_over_table(&vars[idx], vars);
    for f in found {
        vars[f].is_visited = true;
        // C discards the recursive return value (an abort longjmps past it)
        set_variable(f, vars, ctx, cb)?;
    }

    if vars[idx].is_resolved {
        return Ok(true);
    }

    // Marked resolved BEFORE the callback (the C order): an aborting
    // callback leaves the entry burned so a repeated resolve() skips it
    // (RESOLVE2 silent-success vector).
    vars[idx].is_resolved = true;

    let (name, value) = (vars[idx].var_name.clone(), vars[idx].value.clone());
    cb(ctx, &name, &value)
}

/// void resolve(list&, cb): C's early `return` on the first false callback
/// surfaces as Ok(()) here; a ParseAbort propagates for the caller's
/// stuck-state handling.
pub fn resolve<Ctx>(
    vars: &mut [WeakVariable],
    ctx: &mut Ctx,
    cb: ParseCallback<Ctx>,
) -> Result<(), ParseAbort> {
    let n = vars.len(); // range-for span snapshot
    for i in 0..n {
        // C: if (!var->is_resolved and !set_variable(...)) return; — the
        // `and` short-circuits exactly like Rust's `&&`.
        if !vars[i].is_resolved && !set_variable(i, vars, ctx, cb)? {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ctx {
        calls: Vec<String>,
        fail_on: Option<String>,
        abort_on: Option<String>,
    }

    fn cb(ctx: &mut Ctx, name: &str, value: &str) -> Result<bool, ParseAbort> {
        ctx.calls.push(format!("{name}={value}"));
        if ctx.abort_on.as_deref() == Some(name) {
            return Err(ParseAbort(format!("boom {name}")));
        }
        if ctx.fail_on.as_deref() == Some(name) {
            return Ok(false);
        }
        Ok(true)
    }

    #[test]
    fn extract_names_scan() {
        assert_eq!(extract_variable_names("plain"), Vec::<String>::new());
        assert_eq!(extract_variable_names("$A $B2"), vec!["A", "B2"]);
        assert_eq!(extract_variable_names("$"), vec![""]);
        assert_eq!(extract_variable_names("a$b_c-d"), vec!["b_c"]);
        assert_eq!(extract_variable_names("$$X"), vec!["", "X"]);
        assert_eq!(extract_variable_names("$A$"), vec!["A", ""]);
        assert_eq!(extract_variable_names("$$"), vec!["", ""]);
    }

    #[test]
    fn find_over_table_case_sensitive_first_match() {
        let vars = vec![
            WeakVariable::new("NET0", "[1.2.3.4]"),
            WeakVariable::new("net0", "[5.6.7.8]"),
        ];
        assert_eq!(find_over_table(&WeakVariable::new("X", "$net0"), &vars), vec![1]);
        assert_eq!(find_over_table(&WeakVariable::new("X", "$NET0"), &vars), vec![0]);
        let mut vars2 = vars.clone();
        vars2[0].is_visited = true;
        assert_eq!(find_over_table(&WeakVariable::new("X", "$NET0"), &vars2), Vec::<usize>::new());
    }

    #[test]
    fn resolve_recursive_order() {
        // NET1 depends on NET0 WITHIN the list: depth-first, dependency first.
        let mut vars = vec![
            WeakVariable::new("NET1", "$NET0"),
            WeakVariable::new("NET0", "[3.3.3.3]"),
        ];
        let mut ctx = Ctx { calls: vec![], fail_on: None, abort_on: None };
        resolve(&mut vars, &mut ctx, cb).unwrap();
        assert_eq!(ctx.calls, vec!["NET0=[3.3.3.3]", "NET1=$NET0"]);
    }

    #[test]
    fn early_return_skips_remaining_unresolved() {
        // RESOLVENETS: NET1's callback false -> resolve returns BEFORE
        // NETBAD ever sees a callback.
        let mut vars = vec![
            WeakVariable::new("NET1", "$NET0"),
            WeakVariable::new("NETBAD", "$NOPE"),
        ];
        let mut ctx = Ctx { calls: vec![], fail_on: Some("NET1".into()), abort_on: None };
        resolve(&mut vars, &mut ctx, cb).unwrap();
        assert_eq!(ctx.calls, vec!["NET1=$NET0"]);
    }

    #[test]
    fn abort_burns_resolved_flag() {
        // is_resolved set TRUE BEFORE the aborting callback -> a second
        // pass skips the entry entirely (RESOLVE2 silent-success vector).
        let mut vars = vec![WeakVariable::new("$BAD", "[80:x]")];
        let mut ctx = Ctx { calls: vec![], fail_on: None, abort_on: Some("$BAD".into()) };
        let r = resolve(&mut vars, &mut ctx, cb);
        assert_eq!(r.unwrap_err(), ParseAbort("boom $BAD".into()));
        assert!(vars[0].is_resolved); // burned before the call
        let r2 = resolve(&mut vars, &mut ctx, cb);
        assert!(r2.is_ok());
        assert_eq!(ctx.calls.len(), 1, "resolved entry skipped on second pass");
    }
}
