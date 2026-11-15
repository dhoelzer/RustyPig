//! Port of the UNIT_TEST Catch2 sections embedded in sfip/sf_ipvar.cc and
//! sfip/sf_vartable.cc (TEST_CASE blocks at the bottom of each file).
//! Expectations are the original C++ CHECK() strings verbatim.
use snort3::sfip::sf_ip::SfIp;
use snort3::sfip::sf_ipvar::*;
use snort3::sfip::sf_returns::SfIpRet;
use snort3::sfip::sf_vartable::Vartable;

/// Mirror of print_var_list() (test_features=true path in all these cases)
fn print_var_list(list: &SfIpNodeList, print_bits: bool) -> String {
    let mut out = String::new();
    for (k, p) in list.iter().enumerate() {
        if p.flags & SFIP_ANY != 0 {
            out.push_str("any");
        } else if p.flags & SFIP_NEGATED != 0 {
            out.push('!');
            out.push_str(&p.ip.ntop(true).unwrap());
        } else {
            out.push_str(&p.ip.ntop(true).unwrap());
        }
        if print_bits && p.flags & SFIP_ANY == 0 {
            out.push_str(&format!("/{}", p.ip.get_bits()));
        }
        if k + 1 < list.len() {
            out.push(',');
        }
    }
    out
}

fn ipstr(s: &str) -> SfIp {
    // C test calls ip->set(src, &bits), which accepts a CIDR suffix and
    // masks; sfvar_ip_in only consults the address, so strip the suffix.
    let base = s.split('/').next().unwrap();
    let mut ip = SfIp::new();
    assert_eq!(ip.set_str(base), SfIpRet::Success, "set failed: {s}");
    ip
}

#[test]
fn sfip_var_list_merge() {
    let mut table = Vartable::new();

    // ----- basic list merge -----
    let (e, _) = table.add_str("foo [ 192.168.0.1, 192.168.5.0, 192.168.0.2, 255.255.248.0 ] ");
    assert_eq!(e, SfIpRet::Success);
    let (e, _) = table.add_str("goo [ 255.255.241.0, 192.168.2.1] ");
    assert_eq!(e, SfIpRet::Success);
    let mut var1 = table.lookup_var("foo").unwrap().clone();
    let var2t = table.lookup_var("goo").unwrap().clone();
    assert_eq!(
        print_var_list(&var1.head, false),
        "192.168.0.1,192.168.0.2,192.168.5.0,255.255.248.0"
    );
    assert_eq!(print_var_list(&var2t.head, false), "192.168.2.1,255.255.241.0");

    // add list var2 to list var1, a merge_list() will be called
    assert_eq!(sfvar_add(&mut var1, &var2t), SfIpRet::Success);
    // the merged list should be sorted as well
    assert_eq!(
        print_var_list(&var1.head, false),
        "192.168.0.1,192.168.0.2,192.168.2.1,192.168.5.0,255.255.241.0,255.255.248.0"
    );
    // address contains variable, it will merge the list from $variable
    let (ret, _) = table.add_str("moo [ $goo, 192.168.6.1] ");
    assert_eq!(ret, SfIpRet::Success);
    let var2 = table.lookup_var("moo").unwrap().clone();
    assert_eq!(
        print_var_list(&var2.head, false),
        "192.168.2.1,192.168.6.1,255.255.241.0"
    );

    // add CIDR addresses
    let (ret, _) = table.add_str(
        "my_cidr [ 192.168.0.0/16, f0:e0:d0:c0::8/64, 10.10.1.8/19, f0:e0:d1:c1::1/32]",
    );
    assert_eq!(ret, SfIpRet::Success);
    let mut var2 = table.lookup_var("my_cidr").unwrap().clone();
    assert_eq!(
        print_var_list(&var2.head, false),
        "10.10.0.0,192.168.0.0,00f0:00e0:0000:0000:0000:0000:0000:0000"
    );

    // merge the list (C++ merges the same mutated var1 object)
    assert_eq!(sfvar_add(&mut var2, &var1), SfIpRet::Success);
    assert_eq!(
        print_var_list(&var2.head, false),
        "10.10.0.0,192.168.0.0,255.255.241.0,255.255.248.0,\
00f0:00e0:0000:0000:0000:0000:0000:0000"
    );

    // merge the list again; should yield the same result
    let mut var1 = var1.clone();
    assert_eq!(sfvar_add(&mut var1, &var2), SfIpRet::Success);
    assert_eq!(
        print_var_list(&var1.head, false),
        "10.10.0.0,192.168.0.0,255.255.241.0,255.255.248.0,\
00f0:00e0:0000:0000:0000:0000:0000:0000"
    );

    // ----- merge related IPs -----
    let table = Vartable::new();
    let mut t2 = table;
    assert_eq!(
        t2.add_str("ip11 [ 192.168.255.1/20, 192.168.255.2]").0,
        SfIpRet::Success
    );
    assert_eq!(
        t2.add_str("ip12 [192.168.255.1/21, 192.168.255.2/31]").0,
        SfIpRet::Success
    );
    let mut var1 = t2.lookup_var("ip11").unwrap().clone();
    let var2 = t2.lookup_var("ip12").unwrap().clone();
    assert_eq!(sfvar_add(&mut var1, &var2), SfIpRet::Success);
    assert_eq!(print_var_list(&var1.head, true), "192.168.240.0/116");

    assert_eq!(
        t2.add_str("ip21 [ 1.2.3.8, 1.2.3.9, 1.2.3.10]").0,
        SfIpRet::Success
    );
    assert_eq!(t2.add_str("ip22 [11.2.3.255/25 ]").0, SfIpRet::Success);
    let mut var1 = t2.lookup_var("ip21").unwrap().clone();
    let var2 = t2.lookup_var("ip22").unwrap().clone();
    assert_eq!(sfvar_add(&mut var1, &var2), SfIpRet::Success);
    assert_eq!(
        print_var_list(&var1.head, true),
        "1.2.3.8/128,1.2.3.9/128,1.2.3.10/128,11.2.3.128/121"
    );

    assert_eq!(t2.add_str("ip31 [ 10.9.8.7 ]").0, SfIpRet::Success);
    assert_eq!(t2.add_str("ip32 [ !10.9.8.7 ]").0, SfIpRet::Success);
    let mut var1 = t2.lookup_var("ip31").unwrap().clone();
    let var2 = t2.lookup_var("ip32").unwrap().clone();
    assert_eq!(sfvar_add(&mut var1, &var2), SfIpRet::Success);
    assert_eq!(print_var_list(&var1.head, true), "10.9.8.7/128");
    assert_eq!(print_var_list(&var1.neg_head, true), "!10.9.8.7/128");

    // Duplicate ip in lists of a single ip
    assert_eq!(t2.add_str("once [ 1.1.1.1/16 ]").0, SfIpRet::Success);
    assert_eq!(t2.add_str("again [ 1.1.1.1/16 ]").0, SfIpRet::Success);
    let mut var1 = t2.lookup_var("once").unwrap().clone();
    let var2 = t2.lookup_var("again").unwrap().clone();
    assert_eq!(sfvar_add(&mut var1, &var2), SfIpRet::Success);
    assert_eq!(print_var_list(&var1.head, false), "1.1.0.0");

    // Subset of ip in lists of a single ip
    assert_eq!(t2.add_str("single [ 1.1.1.1 ]").0, SfIpRet::Success);
    assert_eq!(t2.add_str("similar [ 1.1.1.1/16 ]").0, SfIpRet::Success);
    let mut var1 = t2.lookup_var("single").unwrap().clone();
    let var2 = t2.lookup_var("similar").unwrap().clone();
    assert_eq!(sfvar_add(&mut var1, &var2), SfIpRet::Success);
    assert_eq!(print_var_list(&var1.head, false), "1.1.0.0");
}

#[test]
fn sfip_var_merge_contained_and_negated() {
    let mut table = Vartable::new();
    assert_eq!(
        table.add_str("foo 1.2.3.4, cafe:feed:beef::0/48").0,
        SfIpRet::Success
    );
    let mut var1 = table.lookup_var("foo").unwrap().clone();
    assert_eq!(
        table.add_to_var(&mut var1, "1.2.3.5/24, cafe:feed::0/16"),
        SfIpRet::Success
    );
    assert_eq!(
        table.add_to_var(&mut var1, "!9.8.7.6, !dead:beef:abcd::5"),
        SfIpRet::Success
    );
    assert_eq!(
        table.add_to_var(&mut var1, "!9.8.5.4/8, cafe:feed:abcd::0"),
        SfIpRet::Success
    );
    assert_eq!(
        table.add_to_var(&mut var1, "!9.8.3.2, 1.2.6.7/16"),
        SfIpRet::Success
    );
    assert_eq!(
        table.add_to_var(&mut var1, "1.2.3.4/32, cafe:feed::0"),
        SfIpRet::Success
    );
    assert_eq!(
        table.add_to_var(&mut var1, "!dead:beef:abcd::0/32"),
        SfIpRet::Success
    );

    /* Check merged IP lists */
    assert_eq!(
        print_var_list(&var1.head, false),
        "1.2.0.0,cafe:0000:0000:0000:0000:0000:0000:0000"
    );
    assert_eq!(
        print_var_list(&var1.neg_head, false),
        "!9.0.0.0,!dead:beef:0000:0000:0000:0000:0000:0000"
    );

    /* Check lookups */
    assert!(!sfvar_ip_in(&var1, &ipstr("9.8.3.2")));
    assert!(sfvar_ip_in(&var1, &ipstr("1.2.3.4/24")));
    assert!(!sfvar_ip_in(&var1, &ipstr("dead:beef::0")));
    assert!(sfvar_ip_in(&var1, &ipstr("cafe:abcd::9999")));
}

#[test]
fn sfip_var_merge_without_table() {
    let mut var2 = SfIpVar::default();
    let mut table = Vartable::new();

    // 'foo' variable
    assert_eq!(table.add_str("foo 1.0.0.1").0, SfIpRet::Success);

    // no table used
    assert_eq!(sfvar_parse_iplist(None, &mut var2, "1.0.0.2", false), SfIpRet::Success);
    assert_eq!(
        sfvar_parse_iplist(None, &mut var2, "$foo", false),
        SfIpRet::LookupUnavailable
    );
    assert_eq!(
        sfvar_parse_iplist(None, &mut var2, "$moo", false),
        SfIpRet::LookupUnavailable
    );
    assert_eq!(print_var_list(&var2.head, false), "1.0.0.2");

    assert!(!sfvar_ip_in(&var2, &ipstr("1.0.0.1")));
    assert!(sfvar_ip_in(&var2, &ipstr("1.0.0.2")));

    // using table
    let tbl = &table;
    assert_eq!(
        sfvar_parse_iplist(Some(tbl), &mut var2, "$foo", false),
        SfIpRet::Success
    );
    assert_eq!(
        sfvar_parse_iplist(Some(tbl), &mut var2, "$moo", false),
        SfIpRet::LookupFailure
    );
    assert_eq!(print_var_list(&var2.head, false), "1.0.0.1,1.0.0.2");

    assert!(sfvar_ip_in(&var2, &ipstr("1.0.0.1")));
    assert!(sfvar_ip_in(&var2, &ipstr("1.0.0.2")));
}

#[test]
fn sfip_var_copy_add_compare() {
    let mut table = Vartable::new();
    assert_eq!(
        table
            .add_str("foo [ 192.168.0.1, 192.168.5.0, 192.168.0.2, 255.255.248.0 ] ")
            .0,
        SfIpRet::Success
    );
    let var1t = table.lookup_var("foo").unwrap().clone();
    assert_eq!(
        print_var_list(&var1t.head, false),
        "192.168.0.1,192.168.0.2,192.168.5.0,255.255.248.0"
    );
    // deep copy the list
    let var2 = sfvar_deep_copy(&var1t);
    // compare to original
    assert_eq!(
        sfvar_compare(Some(&var1t), Some(&var2)),
        SfIpRet::Equal
    );

    // add a negate node to original list
    let (node, _) = sfipnode_alloc("!192.168.3.2");
    let node = node.expect("alloc !192.168.3.2");
    let mut var1 = var1t;
    assert_eq!(sfvar_add_node(&mut var1, node, true), SfIpRet::Success);
    assert_eq!(print_var_list(&var1.neg_head, false), "!192.168.3.2");
    // now compare should fail
    assert_eq!(
        sfvar_compare(Some(&var1), Some(&var2)),
        SfIpRet::Failure
    );

    // add a node
    let (node, _) = sfipnode_alloc("192.168.90.9");
    let node = node.expect("alloc 192.168.90.9");
    assert_eq!(sfvar_add_node(&mut var1, node, false), SfIpRet::Success);
    assert_eq!(
        print_var_list(&var1.head, false),
        "192.168.0.1,192.168.0.2,192.168.5.0,192.168.90.9,255.255.248.0"
    );
}

#[test]
fn sfip_var_any() {
    let mut table = Vartable::new();
    assert_eq!(table.add_str("foo [any] ").0, SfIpRet::Success);
    let var2t = table.lookup_var("foo").unwrap().clone();
    assert_eq!(print_var_list(&var2t.head, false), "any");

    // try to add list to any
    assert_eq!(
        table.add_str("goo [ 255.255.241.0, 192.168.2.1] ").0,
        SfIpRet::Success
    );
    let mut var1 = var2t;
    let var2 = table.lookup_var("goo").unwrap().clone();
    assert_eq!(sfvar_add(&mut var1, &var2), SfIpRet::Success);
    // adding something to any should not change any
    assert_eq!(print_var_list(&var1.head, false), "any");

    // create a list and add any to it
    let (node, _) = sfipnode_alloc("any");
    let node = node.expect("alloc any");
    assert_eq!(sfvar_add_node(&mut var1, node, false), SfIpRet::Success);

    // after adding any, the original list should have any only
    assert_eq!(print_var_list(&var1.head, false), "any");
    assert_eq!(var1.head_count, 1);
}

#[test]
fn sf_var_table_kitchen_sink() {
    let mut table = Vartable::new();

    /* Parsing tests: these are all valid */
    assert_eq!(
        table.add_str("foo [ 1.2.0.0/16, ffff:dead:beef::0 ] ").0,
        SfIpRet::Success
    );
    assert_eq!(table.add_str(" goo [ ffff:dead:beef::0 ] ").0, SfIpRet::Success);
    assert_eq!(table.add_str(" moo [ any ] ").0, SfIpRet::Success);

    /* Test variable redefine */
    assert_eq!(
        table
            .add_str(" goo [ 192.168.0.1, 192.168.0.2, 192.168.255.0 255.255.248.0 ] ")
            .0,
        SfIpRet::Duplicate
    );

    /* Bogus arguments: all must fail */
    for bad in [
        " phlegm ",
        " phlegm [",
        " phlegm [ ",
        " phlegm [sdfg ",
        " phlegm [ sdfg, 12.123.1.4.5 }",
        " [ 12.123.1.4.5 ]",
        "",
    ] {
        assert_eq!(table.add_str(bad).0, SfIpRet::Failure, "input {bad:?}");
    }

    /* Containment tests */
    let var = table.lookup_var("goo").unwrap().clone();
    assert!(!sfvar_ip_in(&var, &ipstr("192.168.248.255")));

    /* Check against the 'any' variable */
    let var = table.lookup_var("moo").unwrap().clone();
    assert!(sfvar_ip_in(&var, &ipstr("192.168.248.255")));

    /* Verify it's not in this variable */
    let var = table.lookup_var("foo").unwrap().clone();
    assert!(!sfvar_ip_in(&var, &ipstr("192.168.248.255")));

    /* Check boundary cases */
    let var = table.lookup_var("goo").unwrap().clone();
    assert!(!sfvar_ip_in(&var, &ipstr("192.168.0.3")));
    assert!(sfvar_ip_in(&var, &ipstr("192.168.0.2")));
}
