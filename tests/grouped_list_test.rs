// Port of src/helpers/test/grouped_list_test.cc — sections 1:1.

use snort3::helpers::grouped_list::{ElemRef, GroupedList};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
struct Type {
    id: i32,
    name: String,
}

impl Type {
    fn _unused(&self) {}
}

fn t(id: i32, name: &str) -> Type {
    Type { id, name: name.to_string() }
}

fn check_container(
    cont: &GroupedList<Type>,
    data: &[Type],
) {
    let got: Vec<&Type> = cont.container_values();
    assert_eq!(got.len(), data.len(), "container length mismatch");
    for (g, d) in got.iter().zip(data) {
        assert_eq!(*g, d);
    }
}

#[test]
fn basic() {
    // SECTION no data
    {
        let cont = GroupedList::<Type>::new();
        check_container(&cont, &[]);
    }
    // SECTION 1 element
    {
        let mut cont = GroupedList::<Type>::new();
        let group = cont.new_group();
        let data = t(1, "one");
        let el = cont.append(group, data.clone());
        assert_ne!(el, ElemRef(0)); // el != nullptr (holder idx would mean null)
        check_container(&cont, &[data]);
    }
    // SECTION 3 elements
    {
        let mut cont = GroupedList::<Type>::new();
        let group = cont.new_group();
        let (d1, d2, d3) = (t(1, "one"), t(2, "two"), t(3, "three"));
        let el1 = cont.append(group, d1.clone());
        let el2 = cont.append(group, d2.clone());
        let el3 = cont.append(group, d3.clone());
        assert_ne!(el1, ElemRef(0));
        assert_ne!(el2, ElemRef(0));
        assert_ne!(el3, ElemRef(0));
        check_container(&cont, &[d1, d2, d3]);
    }
}

#[test]
fn groups_3_element_group() {
    let mut cont = GroupedList::<Type>::new();
    let ga = cont.new_group();
    let (d1, d2, d3) = (t(1, "one"), t(2, "two"), t(3, "three"));
    let el1 = cont.append(ga, d1.clone());
    assert_eq!(cont.group_head(ga), Some(el1));
    let el2 = cont.append(ga, d2.clone());
    assert_eq!(cont.group_head(ga), Some(el2));
    let el3 = cont.append(ga, d3.clone());
    assert_eq!(cont.group_head(ga), Some(el3));

    check_container(&cont, &[d1, d2, d3]);

    let cnt = cont.erase_group(ga);
    assert_eq!(cnt, 3);
    assert_eq!(cont.group_head(ga), None);

    check_container(&cont, &[]);
}

#[test]
fn groups_3_groups() {
    let mut cont = GroupedList::<Type>::new();
    let (ga, gb, gc) = (cont.new_group(), cont.new_group(), cont.new_group());
    let (d1, d2, d3) = (t(1, "one"), t(2, "two"), t(3, "three"));
    let el1 = cont.append(ga, d1.clone());
    assert_eq!(cont.group_head(ga), Some(el1));
    let el2 = cont.append(gb, d2.clone());
    assert_eq!(cont.group_head(gb), Some(el2));
    let el3 = cont.append(gc, d3.clone());
    assert_eq!(cont.group_head(gc), Some(el3));

    check_container(&cont, &[d1.clone(), d2.clone(), d3.clone()]);

    assert_eq!(cont.erase_group(ga), 1);
    assert_eq!(cont.group_head(ga), None);
    check_container(&cont, &[d2.clone(), d3.clone()]);

    assert_eq!(cont.erase_group(gb), 1);
    assert_eq!(cont.group_head(gb), None);
    check_container(&cont, std::slice::from_ref(&d3));

    assert_eq!(cont.erase_group(gc), 1);
    assert_eq!(cont.group_head(gc), None);
    check_container(&cont, &[]);
}

#[test]
fn groups_interleaving() {
    let mut cont = GroupedList::<Type>::new();
    let (ga, gb, gc) = (cont.new_group(), cont.new_group(), cont.new_group());
    let (d1, d2, d3) = (t(1, "one"), t(2, "two"), t(3, "three"));
    for _ in 0..3 {
        cont.append(ga, d1.clone());
        cont.append(gb, d2.clone());
        cont.append(gc, d3.clone());
    }
    check_container(&cont, &[
        d1.clone(), d2.clone(), d3.clone(),
        d1.clone(), d2.clone(), d3.clone(),
        d1.clone(), d2.clone(), d3.clone(),
    ]);

    assert_eq!(cont.erase_group(ga), 3);
    assert_eq!(cont.group_head(ga), None);
    check_container(&cont, &[
        d2.clone(), d3.clone(), d2.clone(), d3.clone(), d2.clone(), d3.clone(),
    ]);

    assert_eq!(cont.erase_group(gb), 3);
    check_container(&cont, &[d3.clone(), d3.clone(), d3.clone()]);

    assert_eq!(cont.erase_group(gc), 3);
    check_container(&cont, &[]);
}

#[test]
fn leaving_group_middle() {
    let mut cont = GroupedList::<Type>::new();
    let ga = cont.new_group();
    let (d1, d2, d3) = (t(1, "one"), t(2, "two"), t(3, "three"));
    let el1 = cont.append(ga, d1.clone());
    assert_eq!(cont.group_head(ga), Some(el1));
    let el2 = cont.append(ga, d2.clone());
    assert_eq!(cont.group_head(ga), Some(el2));
    let el3 = cont.append(ga, d3.clone());
    assert_eq!(cont.group_head(ga), Some(el3));

    check_container(&cont, &[d1.clone(), d2.clone(), d3.clone()]);

    cont.leave_group(el2);
    cont.delete_element(el2);
    assert_eq!(cont.group_head(ga), Some(el3));

    check_container(&cont, &[d1.clone(), d3.clone()]);

    assert_eq!(cont.erase_group(ga), 2);
    assert_eq!(cont.group_head(ga), None);
    check_container(&cont, &[]);
}

#[test]
fn leaving_group_begin() {
    let mut cont = GroupedList::<Type>::new();
    let ga = cont.new_group();
    let (d1, d2, d3) = (t(1, "one"), t(2, "two"), t(3, "three"));
    let el1 = cont.append(ga, d1.clone());
    assert_eq!(cont.group_head(ga), Some(el1));
    let el2 = cont.append(ga, d2.clone());
    assert_eq!(cont.group_head(ga), Some(el2));
    let el3 = cont.append(ga, d3.clone());
    assert_eq!(cont.group_head(ga), Some(el3));

    check_container(&cont, &[d1.clone(), d2.clone(), d3.clone()]);

    // "begin" here is group-chain beginning == FIRST inserted (el1)
    cont.leave_group(el1);
    cont.delete_element(el1);
    assert_eq!(cont.group_head(ga), Some(el3));

    check_container(&cont, &[d2.clone(), d3.clone()]);

    assert_eq!(cont.erase_group(ga), 2);
    check_container(&cont, &[]);
}

#[test]
fn leaving_group_end() {
    let mut cont = GroupedList::<Type>::new();
    let ga = cont.new_group();
    let (d1, d2, d3) = (t(1, "one"), t(2, "two"), t(3, "three"));
    let _el1 = cont.append(ga, d1.clone());
    let el2 = cont.append(ga, d2.clone());
    let el3 = cont.append(ga, d3.clone());
    assert_eq!(cont.group_head(ga), Some(el3));

    check_container(&cont, &[d1.clone(), d2.clone(), d3.clone()]);

    // chain end == group head (most recently appended)
    cont.leave_group(el3);
    cont.delete_element(el3);
    assert_eq!(cont.group_head(ga), Some(el2));

    check_container(&cont, &[d1.clone(), d2.clone()]);

    assert_eq!(cont.erase_group(ga), 2);
    check_container(&cont, &[]);
}

#[test]
fn leaving_group_one_by_one() {
    let mut cont = GroupedList::<Type>::new();
    let ga = cont.new_group();
    let (d1, d2, d3) = (t(1, "one"), t(2, "two"), t(3, "three"));
    let el1 = cont.append(ga, d1.clone());
    let el2 = cont.append(ga, d2.clone());
    let el3 = cont.append(ga, d3.clone());

    check_container(&cont, &[d1.clone(), d2.clone(), d3.clone()]);

    cont.leave_group(el3);
    cont.delete_element(el3);
    assert_eq!(cont.group_head(ga), Some(el2));

    cont.leave_group(el2);
    cont.delete_element(el2);
    assert_eq!(cont.group_head(ga), Some(el1));

    cont.leave_group(el1);
    cont.delete_element(el1);
    assert_eq!(cont.group_head(ga), None);

    check_container(&cont, &[]);
}

#[test]
fn leaving_group_repeated_call() {
    let mut cont = GroupedList::<Type>::new();
    let ga = cont.new_group();
    let d: Vec<Type> = (1..=5i32).map(|i| t(i, ["zero", "one", "two", "three", "four", "five"][i as usize])).collect();
    let els: Vec<ElemRef> = d.iter().cloned().map(|v| cont.append(ga, v)).collect();

    check_container(&cont, &d);

    for k in [0, 0, 0, 2, 2, 2, 4, 4, 4] {
        cont.leave_group(els[k]);
    }

    assert_eq!(cont.group_head(ga), Some(els[3]));
    check_container(&cont, &d);

    for e in els {
        cont.delete_element(e);
    }
}

#[test]
fn memory_delete_element() {
    let mut cont = GroupedList::<Type>::new();
    let ga = cont.new_group();
    let data = t(1, "one");
    let el = cont.append(ga, data.clone());
    check_container(&cont, std::slice::from_ref(&data));
    cont.delete_element(el);
    check_container(&cont, &[]);
    // C++ leaves group_a dangling but never reads it; cont destructor is next.
}

#[test]
fn memory_delete_group() {
    let mut cont = GroupedList::<Type>::new();
    let ga = cont.new_group();
    let data = t(1, "one");
    cont.append(ga, data.clone());
    check_container(&cont, std::slice::from_ref(&data));
    cont.erase_group(ga);
    assert_eq!(cont.group_head(ga), None);
    check_container(&cont, &[]);
}

#[test]
fn memory_delete_element_then_group() {
    let mut cont = GroupedList::<Type>::new();
    let (ga, gb) = (cont.new_group(), cont.new_group());
    let (d1, d2) = (t(1, "one"), t(2, "two"));
    cont.append(ga, d1.clone());
    let el2 = cont.append(gb, d2.clone());
    cont.delete_element(el2);
    check_container(&cont, std::slice::from_ref(&d1));
    cont.erase_group(ga);
    assert_eq!(cont.group_head(ga), None);
    check_container(&cont, &[]);
}

#[test]
fn memory_delete_group_then_element() {
    let mut cont = GroupedList::<Type>::new();
    let (ga, gb) = (cont.new_group(), cont.new_group());
    let (d1, d2) = (t(1, "one"), t(2, "two"));
    cont.append(ga, d1.clone());
    let el2 = cont.append(gb, d2.clone());
    cont.erase_group(ga);
    check_container(&cont, std::slice::from_ref(&d2));
    cont.delete_element(el2);
    check_container(&cont, &[]);
}

#[test]
fn memory_delete_elements_remain_then_group() {
    let mut cont = GroupedList::<Type>::new();
    let (ga, gb) = (cont.new_group(), cont.new_group());
    let (d1, d2, d3) = (t(1, "one"), t(2, "two"), t(3, "three"));
    cont.append(ga, d1.clone());
    let el2 = cont.append(gb, d2.clone());
    cont.append(gb, d3.clone());
    cont.delete_element(el2);
    check_container(&cont, &[d1.clone(), d3.clone()]);
    cont.erase_group(ga);
    assert_eq!(cont.group_head(ga), None);
    check_container(&cont, std::slice::from_ref(&d3));
}

#[test]
fn memory_delete_group_then_elements_remain() {
    let mut cont = GroupedList::<Type>::new();
    let (ga, gb) = (cont.new_group(), cont.new_group());
    let (d1, d2, d3) = (t(1, "one"), t(2, "two"), t(3, "three"));
    cont.append(ga, d1.clone());
    let el2 = cont.append(gb, d2.clone());
    cont.append(gb, d3.clone());
    cont.erase_group(ga);
    check_container(&cont, &[d2.clone(), d3.clone()]);
    cont.delete_element(el2);
    check_container(&cont, std::slice::from_ref(&d3));
}

#[test]
fn holder_dtor_erase_all() {
    // ~GroupedList for holder == erase_all()
    let mut cont = GroupedList::<Type>::new();
    let ga = cont.new_group();
    cont.append(ga, t(1, "one"));
    cont.append(ga, t(2, "two"));
    let drained = cont.erase_all();
    assert_eq!(drained.len(), 2);
    check_container(&cont, &[]);
}
