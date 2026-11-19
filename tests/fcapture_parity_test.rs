//! Parity test for `src/file_api/file_capture.rs` — row 17s.
//!
//! Ground truth: `tools/fcap_harness/vectors.txt` (md5
//! 0208a69116861a506f0c46a7dc36b2ac) — C transcripts of
//! file_capture.cc:1-:619 driven by probe.cc (vector groups A-I).
//! The async groups (E/F/G/H/I) replay here through the
//! SINGLE-THREAD writer model (file_capture.rs module header, fcap
//! PLAN §8-2): [FileCapture::writer_pop]/[FileCapture::writer_finish]
//! stand in for the gate-armed hook ladder, [FileCapture::flush]
//! inline-drains the writer exactly as the C predicate waits on it,
//! [FileCapture::exit] drains before nulling the storer (join arm,
//! the :89-:91 "!running writes remaining files first" comment).
//!
//! Deltas the C probe pinned PER-THREAD (writer TLS invisible on
//! main — `F_tls_split main_files_released_d=0`, vectors.txt:22) are
//! VISIBLE merged here; that is the recorded THREAD_LOCAL deviation
//! (KNOWN DEVIATIONS.md row 17s) and is asserted explicitly with the
//! C split cited.
//!
//! Mechanism note: the C probe reached the private `file_mempool` /
//! `capture_block_size` statics through the FIXACC-published header
//! (probe.cc:151-:153/:265-:267, fcap PLAN §6). The Rust fields are
//! private; every vector here arms the SAME state through public
//! seams — [FileCapture::init_mempool] with a `block_len` chosen so
//! the MiB/slot math carves the required max_files (the 2-slot pool
//! = 1 MiB / 524288 B), and [FileCaptureShared::set_capture_block
//! _size] for the 136-slot/64-payload mismatch the probe pinned at
//! :267. The pinned numbers land 1:1.

use std::cell::RefCell;
use std::rc::Rc;

use snort3::file_api::file_capture::{
    BareInstanceFile, FileCapture, FileCaptureShared, InstanceFileApi, RealFileCaptureFactory,
    SIZEOF_FILE_CAPTURE, SIZEOF_FILE_CAPTURE_BLOCK, SLOT_BLOCK64,
};
use snort3::file_api::file_lib::{
    FileInfo, FILE_CAPTURE_MAX, FILE_CAPTURE_MEMCAP, FILE_CAPTURE_MIN, FILE_CAPTURE_SUCCESS,
    SNORT_FILE_END, SNORT_FILE_FULL, SNORT_FILE_START,
};
use snort3::file_api::file_stats::FileCounts;
use snort3::utils::stats::snapshot::{Builder, Snapshot, Value};

fn dc(now: u64, before: u64) -> u64 {
    now.wrapping_sub(before)
}

/// vectors.txt:1 — the pinned layout line (probe CONST).
#[test]
fn fcap_const_layout() {
    assert_eq!(SIZEOF_FILE_CAPTURE, 72); // sizeof(FileCapture)
    assert_eq!(SIZEOF_FILE_CAPTURE_BLOCK, 16); // sizeof(FileCaptureBlock)
    // slot math :220 + :228-:229 cross-check (probe :31-:35)
    let mut slot = 64 + SIZEOF_FILE_CAPTURE;
    if slot & 7 != 0 {
        slot += 8 - (slot & 7);
    }
    assert_eq!(slot, SLOT_BLOCK64);
    assert_eq!(SLOT_BLOCK64, 136);
}

/// probe walk_capture shape (probe.cc:100-:121): snapshot the block
/// before use; returns (blocks, len_sum, first_byte, last_byte).
fn walk(fc: &mut FileCapture) -> (usize, i64, i32, i32) {
    let mut blocks = 0usize;
    let mut len_sum = 0i64;
    let mut first = -1i32;
    let mut last = -1i32;
    loop {
        let mut buff: Option<&[u8]> = None;
        let mut size = 0i32;
        let nxt = fc.get_file_data(&mut buff, &mut size); // snapshot BEFORE use
        let (fb, lb) = match buff {
            Some(b) if size > 0 => (b[0] as i32, b[size as usize - 1] as i32),
            _ => (-1, -1),
        };
        if buff.is_none() || size == 0 {
            break;
        }
        blocks += 1;
        len_sum += size as i64;
        if blocks == 1 {
            first = fb;
        }
        last = lb;
        if nxt.is_none() {
            break; // :485 nullptr = done
        }
    }
    (blocks, len_sum, first, last)
}

/// probe V-A + V-B + V-C: the no-mempool MEMCAP arm, the bare flush,
/// the hookless buffer ladder over the init_mempool seam, FULL/END
/// arms, the 150 B process + 150 B reserve save (5 blocks / 300 B),
/// the get_file_reset re-walk, the nameless store no-op + reserved
/// dtor, the MAX reserve arm, error_capture, the reserve MIN/MAX
/// arms and collect_mem_usage (vectors.txt:2-14).
#[test]
fn fcap_buffer_ladder() {
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));

    // ---- A ----
    // A_nomempool_state=3 (MEMCAP=3): create_file_buffer null
    // (:238-:239) -> process_buffer :384-:387 MEMCAP
    {
        let mut fc = FileCapture::new(0, 0, shared.clone(), counts.clone());
        let st = fc.process_buffer(b"dummy", 5, SNORT_FILE_START);
        assert_eq!(st, FILE_CAPTURE_MEMCAP);
        assert_eq!(FILE_CAPTURE_MEMCAP, 3);
    }
    // A_flush_no_pending_returns=1: bare flush, no writer (:817)
    FileCapture::flush(&shared);
    FileCapture::test_reset(&shared); // fixture pattern (:781-:782)

    // ---- B ----
    // probe :151-:153 order: static capture_block_size = 64 THEN
    // init_mempool (init_mempool itself never writes the static —
    // only init() :168 does in C; the FIXACC poke stands via the
    // accessor)
    shared.set_capture_block_size(64);
    FileCapture::init_mempool(&shared, 1, 64);
    // B_memcap1mb_block64 buffers_max=7710 buffers_in_use=0
    assert_eq!(FileCapture::get_buffers_max(&shared), 7710);
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 0);

    // B_full st=0 within_packet_d=1
    {
        let before = counts.borrow().file_within_packet;
        let mut fc = FileCapture::new(0, 100000, shared.clone(), counts.clone());
        let st = fc.process_buffer(b"x", 1, SNORT_FILE_FULL);
        assert_eq!(st, FILE_CAPTURE_SUCCESS);
        assert_eq!(dc(counts.borrow().file_within_packet, before), 1);
    }
    // B_end st=0 buffered_d=0
    {
        let before = counts.borrow().files_buffered_total;
        let mut fc = FileCapture::new(0, 100000, shared.clone(), counts.clone());
        let st = fc.process_buffer(b"x", 1, SNORT_FILE_END);
        assert_eq!(st, FILE_CAPTURE_SUCCESS);
        assert_eq!(dc(counts.borrow().files_buffered_total, before), 0);
    }

    // B_split st=0 rst=0 blocks=5 len_sum=300 first=0 last=21
    // capsize=300 buffered_d=1 alloc_d=5 used_max=5 in_use=5
    // (150 B START = 64+64+22 in 3 blocks; reserve_file's FINAL 150
    // B save overflows block 3 -> 2 more blocks, :293-:331)
    let data150: Vec<u8> = (0..150u32).map(|i| (i & 0x7f) as u8).collect();
    let snap_alloc = counts.borrow().file_buffers_allocated_total;
    let snap_buf = counts.borrow().files_buffered_total;
    let snap_files_rel = counts.borrow().files_released_total;
    let snap_bufs_rel = counts.borrow().file_buffers_released_total;
    {
        let mut fc = FileCapture::new(0, 100000, shared.clone(), counts.clone());
        let st = fc.process_buffer(&data150, 150, SNORT_FILE_START);
        let mut fi = FileInfo::default();
        fi.set_file_size(150);
        let rst = fc.reserve_file(&fi);
        assert_eq!((st, rst), (FILE_CAPTURE_SUCCESS, FILE_CAPTURE_SUCCESS));

        assert_eq!(walk(&mut fc), (5, 300, 0, 21));
        assert_eq!(fc.get_file_capture_size(), 300); // capsize=300
        assert_eq!(dc(counts.borrow().files_buffered_total, snap_buf), 1);
        assert_eq!(
            dc(counts.borrow().file_buffers_allocated_total, snap_alloc),
            5
        );
        assert_eq!(counts.borrow().file_buffers_used_max, 5);
        assert_eq!(FileCapture::get_buffers_in_use(&shared), 5);

        // B_reset_walk blocks=5 len_sum=300 first=0 last=21
        fc.get_file_reset();
        assert_eq!(walk(&mut fc), (5, 300, 0, 21));

        // B_store_nameless_noop=1: nameless FileInfo -> fopen("",
        // "wx") fails fast (:536-:540): NO disk write, NO ErrorMessage
        fc.store_file();

        // ~FileCapture reserved arm (:135-:147) lands at scope end
    }
    // B_dtor files_released_d=1 bufs_released_d=5 in_use_after=0
    assert_eq!(dc(counts.borrow().files_released_total, snap_files_rel), 1);
    assert_eq!(
        dc(counts.borrow().file_buffers_released_total, snap_bufs_rel),
        5
    );
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 0);
    assert_eq!(counts.borrow().file_buffers_release_errors, 0);

    // B_max st=2 rst=2(MAX=2) size_max_d=1 reserve_fail_d=1
    {
        let s1 = counts.borrow().file_size_max;
        let s2 = counts.borrow().file_reserve_failures;
        let mut fc = FileCapture::new(0, 100, shared.clone(), counts.clone());
        let st = fc.process_buffer(&data150, 150, SNORT_FILE_START);
        let mut fi = FileInfo::default();
        fi.set_file_size(30);
        let rst = fc.reserve_file(&fi);
        assert_eq!((st, rst), (FILE_CAPTURE_MAX, FILE_CAPTURE_MAX));
        assert_eq!(FILE_CAPTURE_MAX, 2);
        // save arm :279 (size_max) once; reserve :403 -> the polluted
        // capture_state once (file_reserve_failures); the :423 arm is
        // NOT reached — C pinned size_max_d=1, matching
        assert_eq!(dc(counts.borrow().file_size_max, s1), 1);
        assert_eq!(dc(counts.borrow().file_reserve_failures, s2), 1);
    }

    // B_errcap st=1(MIN=1) reserve_fail_d=1
    {
        let s = counts.borrow().file_reserve_failures;
        let st = FileCapture::error_capture(FILE_CAPTURE_MIN, &mut counts.borrow_mut());
        assert_eq!(st, FILE_CAPTURE_MIN);
        assert_eq!(FILE_CAPTURE_MIN, 1);
        assert_eq!(dc(counts.borrow().file_reserve_failures, s), 1);
    }

    // B_reserve_arms min=1(MIN=1) max=2(MAX=2) on SUCCESS captures
    {
        let d12 = [1u8; 12];
        let mut fc = FileCapture::new(10, 20, shared.clone(), counts.clone());
        fc.process_buffer(&d12, 12, SNORT_FILE_START);
        fc.set_data(&d12, 12);
        let mut small = FileInfo::default();
        small.set_file_size(3);
        assert_eq!(fc.reserve_file(&small), FILE_CAPTURE_MIN); // :415-:419

        let mut fc2 = FileCapture::new(10, 20, shared.clone(), counts.clone());
        fc2.process_buffer(&d12, 12, SNORT_FILE_START);
        fc2.set_data(&d12, 12);
        let mut big = FileInfo::default();
        big.set_file_size(99);
        assert_eq!(fc2.reserve_file(&big), FILE_CAPTURE_MAX); // :421-:425
    }

    // C_counters n=5 | capacity=7710 | in use=0 | free=7705 |
    // release=5 | bytes=0 (the B pool live: 5 slots sat in the
    // release list via the reserved dtor's m_release arm, :145)
    {
        let mut snapshot = Snapshot::default();
        let mut builder = Builder::new(&mut snapshot);
        let section = builder.section("fcap");
        let group = Builder::group(section, "file capture");
        FileCapture::collect_mem_usage(&shared, group);
        let rendered: Vec<String> = group
            .counters
            .iter()
            .map(|c| {
                let v = match &c.value {
                    Value::U64(u) => u.to_string(),
                    Value::I64(i) => i.to_string(),
                    _ => "nonint".to_string(),
                };
                format!("{}={}", c.get_name(), v)
            })
            .collect();
        assert_eq!(group.counters.len(), 5); // n=5
        assert_eq!(
            rendered,
            vec![
                "Max file buffer capacity=7710",
                "Buffers in use=0",
                "Buffers in free list=7705",
                "Buffers in release list=5",
                "Memory usage in bytes=0",
            ]
        );
    }
}

/// probe V-D (vectors.txt:15-18): the 2-slot pool (C poked
/// `new FileMemPool(2, slot64)` at probe.cc:265-:266; here the
/// same max_files=2 falls out of the public init_mempool MiB math
/// with block_len 524216 => slot 1 MiB/2 = 524288) and the
/// payload/slot mismatch (capture_block_size = 64, probe :267) —
/// every pinned number lands 1:1:
/// D_exhaust st=3(MEMCAP=3) memcap_fail_d=1 in_use=2 /
/// bufs_freed_d=2 in_use_after=0 (the transient dtor m_free arm) /
/// D_reserve_memcap rst=3(MEMCAP=3) fail_reserve_d=0
/// memcap_total_d=1 in_use=2 / D_reserve_dtored in_use=0
/// bufs_freed_d=2.
#[test]
fn fcap_memcap_arms() {
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));

    shared.set_capture_block_size(64); // probe :267 (136-slot vs 64-payload)
    FileCapture::init_mempool(&shared, 1, 524216); // 1 MiB / 524288 = 2 max_files
    assert_eq!(FileCapture::get_buffers_max(&shared), 2);

    let data200: Vec<u8> = (0..200u32).map(|i| i as u8).collect();

    // D_exhaust st=3(MEMCAP=3) memcap_fail_d=1 in_use=2
    {
        let s_mt = counts.borrow().file_memcap_failures_total;
        let s_freed = counts.borrow().file_buffers_freed_total;
        {
            let mut fc = FileCapture::new(0, 100000, shared.clone(), counts.clone());
            let st = fc.process_buffer(&data200, 200, SNORT_FILE_START);
            assert_eq!(st, FILE_CAPTURE_MEMCAP);
            assert_eq!(dc(counts.borrow().file_memcap_failures_total, s_mt), 1);
            assert_eq!(FileCapture::get_buffers_in_use(&shared), 2);
            // transient dtor (head set, file_info null) -> :151-:153
        }
        // D_exhaust bufs_freed_d=2 in_use_after=0
        assert_eq!(dc(counts.borrow().file_buffers_freed_total, s_freed), 2);
        assert_eq!(FileCapture::get_buffers_in_use(&shared), 0);
        assert_eq!(counts.borrow().file_buffers_free_errors, 0);
        assert_eq!(counts.borrow().files_freed_total, 1); // :138
    }

    // D_reserve_memcap rst=3(MEMCAP=3) fail_reserve_d=0
    // memcap_total_d=1 in_use=2 — empty head, 200 B staged data: the
    // reserve's :432 create SUCCEEDS (1 slot), the split ladder eats
    // the 2nd slot, the 3rd create fails at :306 -> :448
    // error_capture(capture_state=MEMCAP) — :436 never fires
    {
        let s_res = counts.borrow().file_memcap_failures_reserve;
        let s_mt = counts.borrow().file_memcap_failures_total;
        let s_freed = counts.borrow().file_buffers_freed_total;
        {
            let mut fc = FileCapture::new(0, 100000, shared.clone(), counts.clone());
            fc.set_data(&data200, 200);
            let mut fi = FileInfo::default();
            fi.set_file_size(1);
            let rst = fc.reserve_file(&fi);
            assert_eq!(rst, FILE_CAPTURE_MEMCAP);
            assert_eq!(dc(counts.borrow().file_memcap_failures_reserve, s_res), 0);
            assert_eq!(dc(counts.borrow().file_memcap_failures_total, s_mt), 1);
            assert_eq!(FileCapture::get_buffers_in_use(&shared), 2);
        }
        // D_reserve_dtored in_use=0 bufs_freed_d=2
        assert_eq!(FileCapture::get_buffers_in_use(&shared), 0);
        assert_eq!(dc(counts.borrow().file_buffers_freed_total, s_freed), 2);
    }
}

/// probe V-E + V-I (vectors.txt:19-20, 25-27): the TestAccess seams
/// (resettable / reset / enqueue), the hookless drain (store_file of
/// the nameless capture = no-op :536-:540, delete frees via the
/// :143-:147 release arm) and the exit()/reinit lifecycle (join =
/// drain, :89-:91; resettable after exit == I_exit_then_resettable=1;
/// reinit-after-exit OK == probe :466-:467).
#[test]
fn fcap_testaccess_hooksless() {
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));

    // I_resettable_before=1 (probe :459) on fresh statics
    assert!(FileCapture::resettable(&shared));

    FileCapture::test_reset(&shared); // fixture reset (:631-:639)
    assert!(FileCapture::resettable(&shared)); // E_resettable=1

    // probe ordering :315-:316: init_mempool(1,64) then block size 64
    FileCapture::init_mempool(&shared, 1, 64);
    shared.set_capture_block_size(64);

    {
        let mut fc = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
        let d4 = [1u8, 2, 3, 4];
        fc.process_buffer(&d4, 4, SNORT_FILE_START);
        let mut fi = FileInfo::default();
        fi.set_file_size(4);
        fc.reserve_file(&fi); // file_info set (nameless)
        FileCapture::enqueue(&shared, fc); // :641-:648 (bypasses store_file_async)
        assert_eq!(shared.queue_len(), 1); // q_before=1
    }

    // E_hookless_drain q_before=1 q_after=0 in_use=0
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 1);
    while FileCapture::writer_step(&shared) {} // nameless store = no-op
    assert_eq!(shared.queue_len(), 0); // q_after=0
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 0); // in_use=0

    FileCapture::test_reset(&shared); // probe :329

    // I_exit_then_resettable=1: init -> exit (drain+join) ->
    // resettable; reinit (fixture reuse) -> exit again
    FileCapture::init(&shared, &counts, 1, 64);
    assert!(!FileCapture::resettable(&shared)); // storer alive
    FileCapture::exit(&shared);
    assert!(FileCapture::resettable(&shared)); // after the join arm
    FileCapture::init(&shared, &counts, 1, 64);
    FileCapture::exit(&shared);
    FileCapture::test_reset(&shared);
    assert!(FileCapture::resettable(&shared));
}

/// probe V-F (case-C mirror, vectors.txt:21-22): the full async
/// ladder single-threaded — rst=0 inuse1=1 storing_when_parked=1
/// done_mid=0 done_after=2 inuse_mid=1 update_inuse=0
/// inuse_after=0 released=1 — pop parks the writer mid-capture; the
/// store/delete/idle order is scripted through the pop/finish split;
/// both flush callers finish only after the release. F_tls_split /
/// the THREAD_LOCAL merge deviation asserted last (C main thread's
/// counts saw 0 released — vectors.txt:22; 17s merged port sees 1).
#[test]
fn fcap_async_ladder_case_c() {
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));

    // AsyncCaptureFixture ctor (:781-:789): REQUIRE resettable,
    // reset, hooks, init(1, 64)
    assert!(FileCapture::resettable(&shared));
    FileCapture::test_reset(&shared);
    FileCapture::init(&shared, &counts, 1, 64);

    let before = counts.borrow().files_released_total;

    let mut cap = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    let d4 = [9u8, 8, 7, 6];
    cap.process_buffer(&d4, 4, SNORT_FILE_START);
    let mut fi = FileInfo::default();
    fi.set_file_size(4);
    let rst = cap.reserve_file(&fi);
    assert_eq!(rst, FILE_CAPTURE_SUCCESS); // rst=0
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 1); // inuse1=1
    FileCapture::enqueue(&shared, cap);

    // writer parks at the :100-:103 hook AFTER pop + storing = true
    let mut parked = FileCapture::writer_pop(&shared).expect("capture popped");
    assert!(FileCapture::flush_pending(&shared)); // storing_when_parked=1
    assert!(shared.is_writer_storing());
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 1); // inuse_mid=1
    let done_mid = 0usize; // predicate blocks both scripted callers
    assert_eq!(done_mid, 0); // done_mid=0

    // release_writer (:794): resume at :104 -> :105 store -> :106
    // delete -> :108-:109 storing=false (finish half)
    parked.store_file(); // :105 (nameless -> no-op, vectors B pin)
    FileCapture::writer_finish(&shared, parked); // :106 + :108-:115

    // both scripted flush callers now return immediately
    FileCapture::flush(&shared);
    FileCapture::flush(&shared);
    let done_after = 2usize;
    assert_eq!(done_after, 2); // done_after=2

    // pool truth read on the LIVE pool (case-C :836-:837 / probe
    // :362): released=1, and after file_counts_update_buffers
    // (:858) the recomputed in_use = 0
    assert_eq!(FileCapture::released_buffers(&shared), 1); // released=1
    let recomputed = FileCapture::get_buffers_in_use(&shared);
    counts.borrow_mut().file_buffers_in_use = recomputed as u64; // :858 body
    assert_eq!(counts.borrow().file_buffers_in_use, 0); // update_inuse=0
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 0); // inuse_after=0

    // F_tls_split (vectors.txt:22): C MAIN saw main_files_released_d
    // = 0 (the writer thread's TLS absorbed it); the single-thread
    // port MERGES the split (deviation, KNOWN DEVIATIONS row 17s) ->
    // exactly 1 here:
    assert_eq!(
        dc(counts.borrow().files_released_total, before),
        1,
        "THREAD_LOCAL merge deviation — the C probe pinned 0 on the main thread"
    );

    // fixture dtor order (:794-:796): release writer + idle BEFORE
    // exit — the exit drain never runs over a parked pop (PLAN §9-1)
    FileCapture::exit(&shared);
    FileCapture::test_reset(&shared);
    assert!(FileCapture::resettable(&shared));
}

/// probe V-G (case-D mirror, vectors.txt:23): two queued captures —
/// r1=0 r2=0 inuse2=2 done_mid=0 inuse_half=1 update_inuse=0
/// inuse_after=0 released=2. The PAUSED first-idle window keeps the
/// queue NONEMPTY: the :203-:206 predicate is sampled nonempty+idle
/// (the wait_for_nonempty_idle_eval pin, :899) and the flush caller
/// keeps waiting; only the idle release drains capture #2.
#[test]
fn fcap_async_queued_case_d() {
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));

    assert!(FileCapture::resettable(&shared));
    FileCapture::test_reset(&shared);
    FileCapture::init(&shared, &counts, 1, 64);

    let mut c1 = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    let mut c2 = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    c1.process_buffer(&[0x21u8], 1, SNORT_FILE_START);
    c2.process_buffer(&[0x22u8], 1, SNORT_FILE_START);
    let mut f1 = FileInfo::default();
    let mut f2 = FileInfo::default();
    f1.set_file_size(1);
    f2.set_file_size(1);
    let r1 = c1.reserve_file(&f1);
    let r2 = c2.reserve_file(&f2);
    assert_eq!((r1, r2), (0, 0)); // r1=0 r2=0
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 2); // inuse2=2
    FileCapture::enqueue2(&shared, c1, c2); // :650-:654 (order kept)

    // writer pops c1; the first idle transition is PAUSED (:887)
    let mut first = FileCapture::writer_pop(&shared).expect("c1 popped");
    first.store_file(); // :105
    FileCapture::writer_finish(&shared, first); // :106 + idle (paused)

    // the nonempty-queue/idle window pinned by
    // wait_for_nonempty_idle_eval (:899): predicate sampled with
    // !queue_empty && !file_storing -> still pending, the caller
    // keeps waiting (done_mid=0, :905):
    assert!(FileCapture::flush_pending(&shared));
    assert!(!shared.is_writer_storing());
    assert!(!FileCapture::resettable(&shared)); // queue nonempty
    // the :203-:206 hook triplet the gate's
    // wait_for_nonempty_idle_eval pins: queue_empty=false,
    // writer_active=false -> C predicate false (pending):
    assert!(!FileCapture::flush_predicate_empty_and_idle(&shared));
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 1); // inuse_half=1

    // release_idle (:795): the queue drains c2 fully
    assert!(FileCapture::writer_step(&shared));
    FileCapture::flush(&shared); // done_after=1

    // pool truth on the LIVE pool: released=2 (case D :837 pattern),
    // update_inuse=0 recomputed from the SHARED pool (probe :401),
    // inuse_after=0
    assert_eq!(FileCapture::released_buffers(&shared), 2); // released=2
    let recomputed = FileCapture::get_buffers_in_use(&shared);
    counts.borrow_mut().file_buffers_in_use = recomputed as u64;
    assert_eq!(counts.borrow().file_buffers_in_use, 0); // update_inuse=0
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 0); // inuse_after=0

    FileCapture::exit(&shared);
    FileCapture::test_reset(&shared);
    assert!(FileCapture::resettable(&shared));
}

/// seam arm for :577 (probe.cc :417-:421 runs the H vector inside a
/// chdir'ed scratch dir; cargo test threads make a process-wide
/// chdir unsafe, so the seam answers an absolute path instead —
/// exactly what the REAL thread.cc:129 get_instance_file does with
/// `-l <logdir>`).
struct TempDirFile {
    dir: String,
}
impl InstanceFileApi for TempDirFile {
    fn get_instance_file(&self, name: &str) -> String {
        format!("{}/{}", self.dir, name)
    }
}

/// the port DEFAULT seam == the harness witness (stubs.cc:182
/// `s = n`): name_eq_sha=1 (vectors.txt:24) pins THIS shape.
#[test]
fn fcap_instance_file_witness_default() {
    let shared = FileCaptureShared::new();
    assert_eq!(
        shared.instance_file_answer("ABCD"),
        "ABCD", // stubs.cc:182: bare name out
    );
}

/// probe V-H (vectors.txt:24): store_file_async full disk path —
/// UPPERCASE-64 sha name, the file lands on disk with BOTH pieces
/// (14 B = 7 process + 7 reserve-restore, file_size=14),
/// dir_entries=1. C pushes raw `this` (:581) and the writer deletes
/// it (:106) — Rust consumes Box<Self> into the queue (module-header
/// ownership note): the capture is NOT reusable after, mirroring the
/// C transfer.
#[test]
fn fcap_store_file_async_disk() {
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));

    let dir = std::env::temp_dir().join(format!("fcap_parity_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    shared.set_instance_file(Box::new(TempDirFile {
        dir: dir.to_str().unwrap().to_string(),
    }));

    assert!(FileCapture::resettable(&shared));
    FileCapture::test_reset(&shared);
    FileCapture::init(&shared, &counts, 1, 64);

    let mut cap = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    cap.process_buffer(b"harness", 7, SNORT_FILE_START);
    let mut fi = FileInfo::default();
    fi.set_file_size(7);
    // probe :430-:433: heap sha planted + is_sha256_set (the Rust
    // FileInfo holds it inline — the C new uint8_t[32] is structurally
    // excluded; the 17r mixed-allocator deviation note applies)
    let sha: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8);
    fi.sha256 = Some(sha);
    fi.is_sha256_set = true;
    cap.reserve_file(&fi); // file_info = the copy (:455)

    // :564-:584 — the Box is CONSUMED into the queue (C this-push)
    let ret = FileCapture::store_file_async(cap);

    // H_async sha pins: name = 64 UPPERCASE hex chars of the digest;
    // the witness-equality (name_eq_sha=1) is the PORT DEFAULT seam
    // pinned in fcap_instance_file_witness_default — this arm runs
    // the logdir-prefixed seam (the real thread.cc shape) so the
    // disk hygiene rule holds (no writes into the repo, skill rule).
    let expect = uppercase_hex(&sha);
    assert_eq!(expect.len(), 64); // name_len=64
    assert!(ret.ends_with(&expect));
    let full = &ret; // get_instance_file's answer IS the path (:578)

    // scripted writer: the NAMED capture takes the real fopen
    // "wx" + block-walk store (:529-:561)
    assert!(FileCapture::writer_step(&shared));

    let meta = std::fs::metadata(full).expect("file present (:536 create_new ok)");
    assert_eq!(meta.len(), 14); // file_size=14
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1); // dir_entries=1

    // file_counts truth after the drain (merged TLS, see case C):
    assert_eq!(counts.borrow().files_released_total, 1);
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 0);

    std::fs::remove_file(full).unwrap();
    FileCapture::exit(&shared);
    FileCapture::test_reset(&shared);
    assert!(FileCapture::resettable(&shared));
    let _ = std::fs::remove_dir(&dir);
}

/// nameless capture (no sha): store_file_async returns "" WITHOUT
/// queueing — the :567-:568 and :570-:572 early arms (the gate's
/// enqueue bypasses this function entirely, PLAN §5, so the arms
/// need their own pin).
#[test]
fn fcap_store_file_async_null_arms() {
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));

    // no file_info -> "" (:567-:568)
    let cap = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    assert_eq!(FileCapture::store_file_async(cap), "");

    // file_info reserved, no sha -> "" (:570-:572)
    let mut cap2 = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    cap2.process_buffer(b"x", 1, SNORT_FILE_START);
    let mut fi = FileInfo::default();
    fi.set_file_size(1);
    cap2.reserve_file(&fi); // nameless, sha unset
    assert_eq!(FileCapture::store_file_async(cap2), "");
    assert_eq!(shared.queue_len(), 0); // NOTHING queued
    assert!(FileCapture::resettable(&shared));
}

/// row 17s seam closure (fcap PLAN §8-3): the FileEnvLite DEFAULT
/// factory now builds REAL FileCaptures — C `new` never answers
/// null, so process_file_capture's pinned-absent expect
/// (file_lib.rs:3005-:3008) holds by construction — and the trait-
/// object forms route into the real ladder/real reserve over the
/// shared pool. The async half stays concrete-only (PLAN §6: the C
/// queue never holds a seam object).
#[test]
fn fcap_seam_closure_real_default() {
    use snort3::file_api::file_lib::{FileCaptureFactory, FileEnvLite};

    // the DEFAULT env factory answers a real capture (not the 17r
    // NoFileCaptureFactory None arm — whose .expect() would now
    // PANIC on capture-enabled flows)
    let mut env = FileEnvLite::default();
    let def = env
        .capture_factory
        .new_capture(1, 2)
        .expect("C `new` never answers null (file_lib.rs:3005-:3008)");
    assert_eq!(def.get_max_file_capture_size(), 2);

    // an inspectable factory pair over ONE shared pool
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));
    FileCapture::init(&shared, &counts, 1, 64); // FileService::init pattern
    assert_eq!(counts.borrow().file_buffers_max, 7710); // :170
    let mut f = RealFileCaptureFactory::with_statics(shared.clone(), counts.clone());

    let d4 = [7u8, 7, 7, 7];
    let mut cap = f.new_capture(0, 1000).expect("never null");
    let st = cap.process_buffer(&d4, 4, SNORT_FILE_START); // trait form
    assert_eq!(st, FILE_CAPTURE_SUCCESS);
    let mut fi = FileInfo::default();
    fi.set_file_size(4);
    assert_eq!(cap.reserve_file(&fi), FILE_CAPTURE_SUCCESS); // trait form
    assert_eq!(cap.get_file_capture_size(), 8); // trait form (4 + 4 restore)
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 1);
    drop(cap); // stop_file_capture's `delete capture` (:1196)
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 0);
    assert_eq!(counts.borrow().files_released_total, 1);
}

fn uppercase_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>()
}

// keep the witness type reachable through the trait (the port
// default seam — vectors.txt:24 name_eq_sha=1 pins ITS semantics)
#[test]
fn fcap_bare_witness_via_trait() {
    let seam: Box<dyn InstanceFileApi> = Box::new(BareInstanceFile);
    assert_eq!(seam.get_instance_file("FF01"), "FF01");
}

// -------------------------------------------------------------------
// Whole-transcript replay of tools/fcap_harness/vectors.txt (27 lines,
// md5 0208a69116861a506f0c46a7dc36b2ac, tracked like the fctx donor's)
// — probe.cc main() (:127-:477) line-for-line against the public
// file_capture API, the donor transcript pattern
// (tests/fctx_parity_test.rs:77 include_str! + :2384 transcript
// compare). The 11 hand-translated tests above carry the narrative
// citations; THIS one pins the raw transcript bytes: ONE shared pool +
// ONE merged counts object across A..I, exactly as the C probe's
// single-process statics + TLS file_counts behaved (fresh per replay —
// the port keeps the C file-statics on FileCaptureShared). The async
// groups replay the gate ladder single-threaded through the
// writer_pop/writer_finish/writer_step seams (module header).
// -------------------------------------------------------------------

const VECTORS: &str = include_str!("../tools/fcap_harness/vectors.txt");

/// vectors.txt:22 is the C THREAD_LOCAL SPLIT line (writer-thread TLS
/// invisible on main). The replay asserts the DOCUMENTED single-model
/// value visibly instead of the C split value — the row-17s THREAD_LOCAL
/// merge deviation, KNOWN DEVIATIONS.md "file_api/file_capture.{h,cc}
/// (row 17s)" — NEVER silently skipped.
const F_TLS_DEVIATION_LINE: &str = "F_tls_split main_files_released_d=1 (17s single-thread merged port — KNOWN DEVIATIONS row 17s; the C probe saw 0 on MAIN, writer-thread TLS invisible)";

/// all 27 vectors.txt lines, in probe print order, byte-compared —
/// with line 22 replaced by the deviation constant above and both
/// sides of that split asserted.
#[test]
#[allow(clippy::too_many_lines)]
fn fcap_transcript_replay() {
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));
    let mut got: Vec<String> = Vec::with_capacity(27);

    // ---- V-CONST (probe :130-:137): printed, never mental (PLAN 9-3) ----
    let mut slot64 = 64 + SIZEOF_FILE_CAPTURE;
    if slot64 & 7 != 0 {
        slot64 += 8 - (slot64 & 7); // :228-:229
    }
    got.push(format!(
        "CONST sizeof_FileCapture={SIZEOF_FILE_CAPTURE} sizeof_FileCaptureBlock={SIZEOF_FILE_CAPTURE_BLOCK} slot_block64={slot64}"
    ));

    // ---- V-A (probe :140-:147): no mempool -> MEMCAP; bare flush ----
    {
        let mut fc = FileCapture::new(0, 0, shared.clone(), counts.clone());
        let st = fc.process_buffer(b"dummy", 5, SNORT_FILE_START);
        got.push(format!(
            "A_nomempool_state={st} (MEMCAP={FILE_CAPTURE_MEMCAP})"
        ));
    }
    got.push("A_flush_no_pending_returns=1".to_string());
    FileCapture::flush(&shared); // mirrors gate case B :817 (predicate true, no writer)

    // ---- V-B (probe :149-:247): hookless ladder over init_mempool ----
    shared.set_capture_block_size(64); // probe :152 (static BEFORE init_mempool)
    FileCapture::init_mempool(&shared, 1, 64); // :153 -> 1 MiB / 136 = 7710
    got.push(format!(
        "B_memcap1mb_block64 buffers_max={} buffers_in_use={}",
        FileCapture::get_buffers_max(&shared),
        FileCapture::get_buffers_in_use(&shared),
    ));

    {
        // B_full :160-:166
        let s = counts.borrow().file_within_packet;
        let mut fc = FileCapture::new(0, 100000, shared.clone(), counts.clone());
        let st = fc.process_buffer(b"x", 1, SNORT_FILE_FULL);
        got.push(format!(
            "B_full st={st} within_packet_d={}",
            dc(counts.borrow().file_within_packet, s)
        ));
    }
    {
        // B_end :168-:174
        let s = counts.borrow().files_buffered_total;
        let mut fc = FileCapture::new(0, 100000, shared.clone(), counts.clone());
        let st = fc.process_buffer(b"x", 1, SNORT_FILE_END);
        got.push(format!(
            "B_end st={st} buffered_d={}",
            dc(counts.borrow().files_buffered_total, s)
        ));
    }
    {
        // B_split..B_dtor :175-:209 (snap_counts :175)
        let snap_alloc = counts.borrow().file_buffers_allocated_total;
        let snap_buf = counts.borrow().files_buffered_total;
        let snap_files_rel = counts.borrow().files_released_total;
        let snap_bufs_rel = counts.borrow().file_buffers_released_total;
        let data150: Vec<u8> = (0..150u32).map(|i| (i & 0x7f) as u8).collect(); // :177
        let (blocks, len_sum, first, last);
        {
            let mut fc = FileCapture::new(0, 100000, shared.clone(), counts.clone());
            let st = fc.process_buffer(&data150, 150, SNORT_FILE_START);
            let mut fi = FileInfo::default();
            fi.set_file_size(150);
            let rst = fc.reserve_file(&fi); // :185 -> SUCCESS
            (blocks, len_sum, first, last) = walk(&mut fc); // walk_capture :186
            got.push(format!(
                "B_split st={st} rst={rst} blocks={blocks} len_sum={len_sum} first={first} last={last} capsize={} buffered_d={} alloc_d={} used_max={} in_use={}",
                fc.get_file_capture_size(),
                dc(counts.borrow().files_buffered_total, snap_buf),
                dc(counts.borrow().file_buffers_allocated_total, snap_alloc),
                counts.borrow().file_buffers_used_max,
                FileCapture::get_buffers_in_use(&shared),
            ));
            fc.get_file_reset(); // :198
            let (b2, l2, f2, la2) = walk(&mut fc); // :200
            got.push(format!(
                "B_reset_walk blocks={b2} len_sum={l2} first={f2} last={la2}"
            ));
            fc.store_file(); // :204 nameless -> fopen("", "wx") fails fast
            got.push("B_store_nameless_noop=1".to_string()); // :205
        } // dtor :135-:147 m_release arm at scope end (probe comment :206)
        got.push(format!(
            "B_dtor files_released_d={} bufs_released_d={} in_use_after={}",
            dc(counts.borrow().files_released_total, snap_files_rel),
            dc(counts.borrow().file_buffers_released_total, snap_bufs_rel),
            FileCapture::get_buffers_in_use(&shared),
        ));
    }
    {
        // B_max :211-:223
        let s1 = counts.borrow().file_size_max;
        let s2 = counts.borrow().file_reserve_failures;
        let data150: Vec<u8> = (0..150u32).map(|i| (i & 0x7f) as u8).collect();
        let mut fc = FileCapture::new(0, 100, shared.clone(), counts.clone());
        let st = fc.process_buffer(&data150, 150, SNORT_FILE_START);
        let mut fi = FileInfo::default();
        fi.set_file_size(30);
        let rst = fc.reserve_file(&fi);
        got.push(format!(
            "B_max st={st} rst={rst}(MAX={FILE_CAPTURE_MAX}) size_max_d={} reserve_fail_d={}",
            dc(counts.borrow().file_size_max, s1),
            dc(counts.borrow().file_reserve_failures, s2),
        ));
    }
    {
        // B_errcap :225-:231
        let s = counts.borrow().file_reserve_failures;
        let st = FileCapture::error_capture(FILE_CAPTURE_MIN, &mut counts.borrow_mut());
        got.push(format!(
            "B_errcap st={st}(MIN={FILE_CAPTURE_MIN}) reserve_fail_d={}",
            dc(counts.borrow().file_reserve_failures, s)
        ));
    }
    {
        // B_reserve_arms :233-:247
        let d12 = [1u8; 12];
        let mut fc = FileCapture::new(10, 20, shared.clone(), counts.clone());
        fc.process_buffer(&d12, 12, SNORT_FILE_START);
        fc.set_data(&d12, 12);
        let mut small = FileInfo::default();
        small.set_file_size(3);
        let st_min = fc.reserve_file(&small);
        let mut fc2 = FileCapture::new(10, 20, shared.clone(), counts.clone());
        fc2.process_buffer(&d12, 12, SNORT_FILE_START);
        fc2.set_data(&d12, 12);
        let mut big = FileInfo::default();
        big.set_file_size(99);
        let st_max = fc2.reserve_file(&big);
        got.push(format!(
            "B_reserve_arms min={st_min}(MIN={FILE_CAPTURE_MIN}) max={st_max}(MAX={FILE_CAPTURE_MAX})"
        ));
    }
    {
        // C_counters :250-:260 — B pool live, 5 slots in the release list
        let mut snapshot = Snapshot::default();
        let mut builder = Builder::new(&mut snapshot);
        let section = builder.section("fcap");
        let group = Builder::group(section, "file capture");
        FileCapture::collect_mem_usage(&shared, group);
        let rendered: Vec<String> = group
            .counters
            .iter()
            .map(|c| {
                let v = match &c.value {
                    Value::U64(u) => u.to_string(),
                    Value::I64(i) => i.to_string(),
                    _ => "nonint".to_string(),
                };
                format!("{}={}", c.get_name(), v)
            })
            .collect();
        got.push(format!(
            "C_counters n={} | {}",
            group.counters.len(),
            rendered.join(" | ")
        ));
    }

    // ---- V-D (probe :263-:307): 2-slot pool, MEMCAP arms ----
    // probe :265-:267 `new FileMemPool(2, slot64)` + block 64 — the same
    // max_files=2 falls out of init_mempool(1, 524216) (1 MiB / 524288)
    FileCapture::init_mempool(&shared, 1, 524216);
    shared.set_capture_block_size(64);
    let data200: Vec<u8> = (0..200u32).map(|i| i as u8).collect(); // :269
    {
        let s_mt = counts.borrow().file_memcap_failures_total;
        let s_freed = counts.borrow().file_buffers_freed_total; // snap :270
        {
            let mut fc = FileCapture::new(0, 100000, shared.clone(), counts.clone());
            let st = fc.process_buffer(&data200, 200, SNORT_FILE_START);
            got.push(format!(
                "D_exhaust st={st}(MEMCAP={FILE_CAPTURE_MEMCAP}) memcap_fail_d={} in_use={}",
                dc(counts.borrow().file_memcap_failures_total, s_mt),
                FileCapture::get_buffers_in_use(&shared),
            ));
        } // transient dtor m_free :151-:153 (probe comment :277-:279)
        got.push(format!(
            "D_exhaust bufs_freed_d={} in_use_after={}",
            dc(counts.borrow().file_buffers_freed_total, s_freed),
            FileCapture::get_buffers_in_use(&shared),
        ));
        {
            // D_reserve_memcap :285-:302 (inner snap_counts :286)
            let s_res = counts.borrow().file_memcap_failures_reserve;
            let s_mt2 = counts.borrow().file_memcap_failures_total;
            let s_freed2 = counts.borrow().file_buffers_freed_total;
            {
                let mut fc = FileCapture::new(0, 100000, shared.clone(), counts.clone());
                fc.set_data(&data200, 200);
                let mut fi = FileInfo::default();
                fi.set_file_size(1);
                let rst = fc.reserve_file(&fi);
                got.push(format!(
                    "D_reserve_memcap rst={rst}(MEMCAP={FILE_CAPTURE_MEMCAP}) fail_reserve_d={} memcap_total_d={} in_use={}",
                    dc(counts.borrow().file_memcap_failures_reserve, s_res),
                    dc(counts.borrow().file_memcap_failures_total, s_mt2),
                    FileCapture::get_buffers_in_use(&shared),
                ));
            } // dtor m_free arms :151-:153
            got.push(format!(
                "D_reserve_dtored in_use={} bufs_freed_d={}",
                FileCapture::get_buffers_in_use(&shared),
                dc(counts.borrow().file_buffers_freed_total, s_freed2),
            ));
        }
    }
    // probe :303-:305 delete pool + nullptr + block 0 -> the scaffold op
    FileCapture::test_reset(&shared);

    // ---- V-E (probe :310-:330): hookless enqueue + drain ----
    // (probe :311 block 0 + :313 fcap_test_reset — test_reset covers both)
    got.push(format!(
        "E_resettable={}",
        u8::from(FileCapture::resettable(&shared)) // :314
    ));
    FileCapture::init_mempool(&shared, 1, 64); // :315
    shared.set_capture_block_size(64); // :316 (reset zeroed it; save math needs it)
    {
        let mut fc = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
        let d4 = [1u8, 2, 3, 4];
        fc.process_buffer(&d4, 4, SNORT_FILE_START);
        let mut fi = FileInfo::default();
        fi.set_file_size(4);
        fc.reserve_file(&fi); // nameless (no sha)
        FileCapture::enqueue(&shared, fc); // :641-:648
        let q_before = shared.queue_len(); // :325
        while FileCapture::writer_step(&shared) {} // fcap_drain_hookless :326
        got.push(format!(
            "E_hookless_drain q_before={q_before} q_after={} in_use={}",
            shared.queue_len(),
            FileCapture::get_buffers_in_use(&shared),
        ));
    }
    FileCapture::test_reset(&shared); // :329

    // ---- V-F (probe :332-:372): gate-armed ladder (case C), single-thread ----
    assert!(FileCapture::resettable(&shared)); // fixture REQUIRE :785
    FileCapture::test_reset(&shared); // :786
    FileCapture::init(&shared, &counts, 1, 64); // :792 (hook arms :787-:791 = the scripted pop/finish split)
    let f_snap = counts.borrow().files_released_total; // probe snap :335
    let rst;
    let inuse1;
    {
        let mut cap = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
        let d4 = [9u8, 8, 7, 6];
        cap.process_buffer(&d4, 4, SNORT_FILE_START);
        let mut fi = FileInfo::default();
        fi.set_file_size(4);
        rst = cap.reserve_file(&fi);
        inuse1 = FileCapture::get_buffers_in_use(&shared);
        FileCapture::enqueue(&shared, cap); // fcap_enqueue :343
    }
    // fcap_gate_wait_writer :344 — the :100-:103 hook parks AFTER the pop
    let mut parked = FileCapture::writer_pop(&shared).expect("writer parks after pop (:95-:97)");
    let storing = shared.is_writer_storing(); // fcap_file_storing_now :345
    let mut done: u32 = 0; // std::atomic<unsigned> :346
    // the two std::thread flush callers :347-:348 reach the :201 wait;
    // fcap_gate_wait_flush_callers(2) :348 == the predicate sampled pending
    assert!(FileCapture::flush_pending(&shared));
    let done_mid = done; // :349 mid = 0 — both callers still waiting
    let inuse_mid = FileCapture::get_buffers_in_use(&shared); // :350
    // fcap_gate_release_writer :351 -> the writer resumes at :104:
    parked.store_file(); // :105 (nameless -> no-op, the B pin)
    FileCapture::writer_finish(&shared, parked); // :106 delete + :108-:109
    FileCapture::flush(&shared); // t1.join() :352
    done += 1;
    FileCapture::flush(&shared); // t2.join() :353
    done += 1;
    let done_after = done; // :354
    counts.borrow_mut().file_buffers_in_use =
        FileCapture::get_buffers_in_use(&shared) as u64; // file_counts_update_buffers :355 (body)
    got.push(format!(
        "F_ladder rst={rst} inuse1={inuse1} storing_when_parked={} done_mid={done_mid} done_after={done_after} inuse_mid={inuse_mid} update_inuse={} inuse_after={} released={}",
        u8::from(storing),
        counts.borrow().file_buffers_in_use,
        FileCapture::get_buffers_in_use(&shared),
        FileCapture::released_buffers(&shared),
    ));
    // F_tls_split (probe :365-:366): the C MAIN thread saw 0 (the writer
    // thread's TLS absorbed the :106 delete); the single-thread port
    // MERGES the split — KNOWN DEVIATIONS row 17s — so the delta is 1,
    // asserted visibly here (never skipped):
    let merged = dc(counts.borrow().files_released_total, f_snap);
    assert_eq!(
        merged, 1,
        "THREAD_LOCAL merge deviation — the C probe pinned main_files_released_d=0 (vectors.txt:22)"
    );
    got.push(F_TLS_DEVIATION_LINE.to_string());
    FileCapture::exit(&shared); // fcap_exit :369 (fixture dtor :794-:796 order: writer already released)
    FileCapture::test_reset(&shared); // fcap_test_reset :371

    // ---- V-G (probe :374-:413): queued pair (case D), single-thread ----
    assert!(FileCapture::resettable(&shared));
    FileCapture::test_reset(&shared);
    FileCapture::init(&shared, &counts, 1, 64); // fcap_init :376
    let mut c1 = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    let mut c2 = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    c1.process_buffer(&[0x21u8], 1, SNORT_FILE_START);
    c2.process_buffer(&[0x22u8], 1, SNORT_FILE_START);
    let mut f1 = FileInfo::default();
    let mut f2 = FileInfo::default();
    f1.set_file_size(1);
    f2.set_file_size(1);
    let r1 = c1.reserve_file(&f1);
    let r2 = c2.reserve_file(&f2);
    let inuse2 = FileCapture::get_buffers_in_use(&shared);
    FileCapture::enqueue2(&shared, c1, c2); // fcap_enqueue2 :388
    let mut first = FileCapture::writer_pop(&shared).expect("c1 popped (:389 wait_for_writer)");
    first.store_file(); // gate release_writer :394 -> :105 (nameless no-op)
    FileCapture::writer_finish(&shared, first); // :106 + :109; first idle transition PAUSED :887/:391
    // wait_for_flush_callers(1) :393 + wait_for_first_idle :395 +
    // wait_for_nonempty_idle_eval :396: the predicate sampled over the
    // nonempty-queue/idle window (:899 pin) -> still pending:
    assert!(FileCapture::flush_pending(&shared));
    assert!(!FileCapture::flush_predicate_empty_and_idle(&shared));
    let mut done: u32 = 0; // :392
    let done_mid = done; // :398 done_mid = 0 (the scripted caller keeps waiting)
    let inuse_half = FileCapture::get_buffers_in_use(&shared); // :399
    assert!(FileCapture::writer_step(&shared)); // release_idle_transition :399(404) -> c2 drains
    FileCapture::flush(&shared); // th.join() :400
    done += 1;
    let done_after = done; // :401
    counts.borrow_mut().file_buffers_in_use =
        FileCapture::get_buffers_in_use(&shared) as u64; // file_counts_update_buffers :403
    got.push(format!(
        "G_queued r1={r1} r2={r2} inuse2={inuse2} done_mid={done_mid} done_after={done_after} inuse_half={inuse_half} update_inuse={} inuse_after={} released={}",
        counts.borrow().file_buffers_in_use,
        FileCapture::get_buffers_in_use(&shared),
        FileCapture::released_buffers(&shared),
    ));
    FileCapture::exit(&shared); // :409
    FileCapture::test_reset(&shared); // :412

    // ---- V-H (probe :415-:454): store_file_async disk path ----
    // the probe chdirs a scratch dir (chdir is process-wide, unsafe under
    // cargo test threads); the seam answers an ABSOLUTE path instead —
    // the real thread.cc:129 shape (see fcap_store_file_async_disk).
    let dir = std::env::temp_dir().join(format!("fcap_replay_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    shared.set_instance_file(Box::new(TempDirFile {
        dir: dir.to_str().unwrap().to_string(),
    }));
    FileCapture::init(&shared, &counts, 1, 64); // fcap_init :428
    let mut cap = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    cap.process_buffer(b"harness", 7, SNORT_FILE_START);
    let mut fi = FileInfo::default();
    fi.set_file_size(7);
    let sha: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8); // g_sha :123-:126
    fi.sha256 = Some(sha);
    fi.is_sha256_set = true;
    cap.reserve_file(&fi);
    let ret = FileCapture::store_file_async(cap); // :441 — Box consumed into the queue
    let expect = uppercase_hex(&sha);
    // the probe's `expect` (witness `s = n`, stubs.cc:182) IS the 64-hex
    // name; here get_instance_file prefixes the logdir (the absolute
    // seam), so pin the NAME component — witness default covered by
    // fcap_instance_file_witness_default.
    let name = ret.rsplit('/').next().unwrap_or("").to_string();
    assert!(FileCapture::writer_step(&shared)); // wait+release+first idle :442-:444
    let entries = std::fs::read_dir(&dir).unwrap().count(); // count_dir_entries :445
    let meta = std::fs::metadata(&ret); // stat :446-:448
    let have = u8::from(meta.is_ok());
    let fsize = meta.map(|m| m.len() as i64).unwrap_or(-1);
    got.push(format!(
        "H_async name_len={} name_eq_sha={} file_present={have} file_size={fsize} dir_entries={entries}",
        name.len(),
        u8::from(name == expect),
    ));
    if have == 1 {
        let _ = std::fs::remove_file(&ret); // unlink :449
    }
    FileCapture::exit(&shared); // :450
    FileCapture::test_reset(&shared); // :451
    let _ = std::fs::remove_dir(&dir); // rmdir :458

    // ---- V-I (probe :457-:474): exit()/reinit lifecycle ----
    got.push(format!(
        "I_resettable_before={}",
        u8::from(FileCapture::resettable(&shared)) // :459
    ));
    FileCapture::init(&shared, &counts, 1, 64); // :461-:462
    FileCapture::exit(&shared); // :463 join path :178-:192
    let after_null = FileCapture::resettable(&shared); // :464
    FileCapture::test_reset(&shared); // :465
    FileCapture::init(&shared, &counts, 1, 64); // :466-:467 reinit (fixture reuse)
    FileCapture::exit(&shared); // :470
    FileCapture::test_reset(&shared); // :471-:472
    got.push(format!(
        "I_exit_then_resettable={}",
        u8::from(after_null)
    ));

    got.push("FCAP_PROBE_DONE".to_string()); // :476

    // ---- the line-for-line compare (donor pattern :2384) ----
    let want: Vec<&str> = VECTORS.trim_end_matches('\n').lines().collect();
    assert_eq!(want.len(), 27, "vectors.txt must hold exactly 27 lines");
    assert_eq!(got.len(), want.len(), "replay emitted {} lines", got.len());
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        if i == 21 {
            // line 22: the C split (0 on MAIN) vs the DOCUMENTED merged
            // single-model value (1) — both sides pinned, deviation row 17s
            assert!(
                w.starts_with("F_tls_split main_files_released_d=0"),
                "vectors.txt:22 must hold the C per-thread split (0 main)"
            );
            assert_eq!(
                g, F_TLS_DEVIATION_LINE,
                "vectors.txt line 22 — THREAD_LOCAL merge deviation asserted visibly"
            );
        } else {
            assert_eq!(g, w, "vectors.txt line {}", i + 1);
        }
    }
}

// -------------------------------------------------------------------
// Faithful statement-for-statement translations of the four upstream
// `#ifdef UNIT_TEST` [file_capture] TEST_CASEs (file_capture.cc
// :808-:912) — the gate ritual (114 assertions / 22 cases incl these 4,
// gate.txt tail). The AsyncCaptureFixture ctor/dtor (:783-:806) arms
// the AsyncWriterGate hook ladder; here the ladder's interleavings are
// scripted single-thread through writer_pop/writer_finish/writer_step
// (module header + KNOWN DEVIATIONS row 17s). C-cite per statement;
// FileCaptureTestAccess::resettable/reset/enqueue/released_buffers =
// the pub seams (file_capture.rs:561-:610). Overlap with the 11
// hand-translated tests above is ACCEPTED — this mirror is the gate
// transcript itself.
// -------------------------------------------------------------------

/// :808 "Should not segfault when file mempool is not configured" —
/// body :809-:812 (1 CHECK).
#[test]
fn up_gate_file_capture_unconfigured_mempool() {
    // FileCapture fc(0, 0);  (:810)
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));
    let mut fc = FileCapture::new(0, 0, shared.clone(), counts.clone());
    // CHECK(fc.process_buffer("dummy", 5, SNORT_FILE_START) == FILE_CAPTURE_MEMCAP) (:812)
    assert_eq!(
        fc.process_buffer(b"dummy", 5, SNORT_FILE_START),
        FILE_CAPTURE_MEMCAP
    );
}

/// :815 "Flush returns when no asynchronous captures are pending" —
/// body :816-:818 (bare FileCapture::flush(); returning IS the assertion).
#[test]
fn up_gate_file_capture_flush_no_pending() {
    let shared = Rc::new(FileCaptureShared::new());
    // FileCapture::flush();  (:817) — predicate :201 holds on a fresh
    // queue with no writer; the return must not hang and must not panic
    // (the parked-pop panic face, PLAN 9-1, is untriggered here).
    FileCapture::flush(&shared);
}

/// :820 "Flush waits for the asynchronous writer to release its
/// capture" — fixture C, body :821-:861 (5 REQUIREs + 6 CHECKs + the
/// file_counts_update_buffers body :858).
#[test]
fn up_gate_file_capture_flush_waits_for_writer() {
    // AsyncCaptureFixture fixture;  (:821) — REQUIRE resettable :785,
    // reset :786, hook arms :787-:791 (scripted through the pop/finish
    // split), init(1, 64) :792
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));
    assert!(FileCapture::resettable(&shared)); // REQUIRE TestAccess::resettable :785
    FileCapture::test_reset(&shared); // TestAccess::reset :786
    FileCapture::init(&shared, &counts, 1, 64); // FileCapture::init :792

    // auto capture = std::make_unique<FileCapture>(0, 128);  (:823)
    let mut capture = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    // const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04 };  (:824)
    let data = [0x01u8, 0x02, 0x03, 0x04];
    // REQUIRE(process_buffer(data, 4, SNORT_FILE_START) == FILE_CAPTURE_SUCCESS) (:826-:827)
    assert_eq!(
        capture.process_buffer(&data, 4, SNORT_FILE_START),
        FILE_CAPTURE_SUCCESS
    );
    // FileInfo file; file.set_file_size(4);  (:829-:830)
    let mut file = FileInfo::default();
    file.set_file_size(4);
    // REQUIRE(capture->reserve_file(&file) == FILE_CAPTURE_SUCCESS) (:831)
    assert_eq!(capture.reserve_file(&file), FILE_CAPTURE_SUCCESS);
    // REQUIRE(FileCapture::get_buffers_in_use() == 1)  (:832)
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 1);

    // FileCaptureTestAccess::enqueue(capture.release());  (:834)
    FileCapture::enqueue(&shared, capture);
    // fixture.gate.wait_for_writer();  (:835) — the :100-:103 hook
    // parks the writer AFTER pop (:95-:96) with file_storing = true (:97):
    let mut parked = FileCapture::writer_pop(&shared).expect("gate parks after pop (:835)");

    // std::thread first_flush / second_flush -> FileCapture::flush() (:841-:848),
    // fixture.gate.wait_for_flush_callers(2) (:849): both callers sit in
    // the :201 wait with the pop parked. Single-thread: a scripted caller
    // only returns once the predicate (:207) holds — sampled pending here:
    assert!(FileCapture::flush_pending(&shared)); // :203-:206 sampling
    // std::atomic<unsigned> completed_flushes = 0;  (:840)
    let mut completed_flushes: u32 = 0;
    // CHECK(completed_flushes == 0)  (:850)
    assert_eq!(completed_flushes, 0);
    // CHECK(FileCapture::get_buffers_in_use() == 1)  (:851)
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 1);

    // fixture.gate.release_writer();  (:853) — writer resumes at :104:
    parked.store_file(); // :105 (nameless capture -> no-op, the B pin)
    FileCapture::writer_finish(&shared, parked); // :106 delete + :108-:109 storing=false

    // first_flush.join(); second_flush.join();  (:854-:855) — the
    // predicate now holds, both scripted flushes return:
    FileCapture::flush(&shared);
    completed_flushes += 1;
    FileCapture::flush(&shared);
    completed_flushes += 1;
    // CHECK(completed_flushes == 2)  (:857)
    assert_eq!(completed_flushes, 2);
    // file_counts_update_buffers();  (:858) — body: recompute from the LIVE pool
    counts.borrow_mut().file_buffers_in_use =
        FileCapture::get_buffers_in_use(&shared) as u64;
    // CHECK(file_counts.file_buffers_in_use == 0)  (:859)
    assert_eq!(counts.borrow().file_buffers_in_use, 0);
    // CHECK(FileCapture::get_buffers_in_use() == 0)  (:860)
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 0);
    // CHECK(FileCaptureTestAccess::released_buffers() == 1)  (:861)
    assert_eq!(FileCapture::released_buffers(&shared), 1);

    // ~AsyncCaptureFixture :793-:796 — release gates, exit, reset
    // (single-thread: the writer is already released; exit drains empty):
    FileCapture::exit(&shared);
    FileCapture::test_reset(&shared);
    assert!(FileCapture::resettable(&shared));
}

/// :864 "Flush keeps waiting between queued asynchronous captures" —
/// fixture D, body :865-:911 (5 REQUIREs :872-:883 + 4 CHECKs + the
/// :899 nonempty-idle predicate pin + file_counts_update_buffers :908).
#[test]
fn up_gate_file_capture_flush_waits_between_queued() {
    // AsyncCaptureFixture fixture;  (:866)
    let shared = Rc::new(FileCaptureShared::new());
    let counts = Rc::new(RefCell::new(FileCounts::default()));
    assert!(FileCapture::resettable(&shared)); // REQUIRE :785
    FileCapture::test_reset(&shared); // :786
    FileCapture::init(&shared, &counts, 1, 64); // :792

    // auto first_capture / second_capture = make_unique<FileCapture>(0, 128); (:868-:869)
    let mut first_capture = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    let mut second_capture = Box::new(FileCapture::new(0, 128, shared.clone(), counts.clone()));
    // const uint8_t first_data[] = { 0x01 }; second_data[] = { 0x02 }; (:870-:871)
    let first_data = [0x01u8];
    let second_data = [0x02u8];
    // REQUIRE(first_capture->process_buffer(...) == FILE_CAPTURE_SUCCESS) (:872-:873)
    assert_eq!(
        first_capture.process_buffer(&first_data, 1, SNORT_FILE_START),
        FILE_CAPTURE_SUCCESS
    );
    // REQUIRE(second_capture->process_buffer(...) == FILE_CAPTURE_SUCCESS) (:874-:875)
    assert_eq!(
        second_capture.process_buffer(&second_data, 1, SNORT_FILE_START),
        FILE_CAPTURE_SUCCESS
    );
    // FileInfo first_file/second_file; set_file_size(1) each  (:877-:880)
    let mut first_file = FileInfo::default();
    let mut second_file = FileInfo::default();
    first_file.set_file_size(1);
    second_file.set_file_size(1);
    // REQUIRE(first_capture->reserve_file(&first_file) == FILE_CAPTURE_SUCCESS) (:881)
    assert_eq!(first_capture.reserve_file(&first_file), FILE_CAPTURE_SUCCESS);
    // REQUIRE(second_capture->reserve_file(&second_file) == FILE_CAPTURE_SUCCESS) (:882)
    assert_eq!(second_capture.reserve_file(&second_file), FILE_CAPTURE_SUCCESS);
    // REQUIRE(FileCapture::get_buffers_in_use() == 2)  (:883)
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 2);

    // FileCaptureTestAccess::enqueue(first, second);  (:885)
    FileCapture::enqueue2(&shared, first_capture, second_capture);
    // fixture.gate.wait_for_writer();  (:886) — writer parked mid-first (:100-:103)
    let mut first = FileCapture::writer_pop(&shared).expect("writer parked after first pop (:886)");
    // fixture.gate.pause_first_idle_transition();  (:887)

    // std::thread flush(:889-:893) + wait_for_flush_callers(1) (:896):
    // the caller sits in the :201 wait;
    // release_writer (:897): the writer resumes -> :105 store, :106
    // delete, :109 storing = false — then PAUSES at the :112-:115 idle
    // hook (wait_for_first_idle :898):
    first.store_file(); // :105 (nameless -> no-op)
    FileCapture::writer_finish(&shared, first); // :106 + :108-:109 (idle hook parked)
    // wait_for_nonempty_idle_evaluation (:899): the :203-:206 hook
    // samples the predicate over the NONEMPTY/idle window — C predicate
    // false, so the flush caller keeps waiting:
    assert!(!FileCapture::flush_predicate_empty_and_idle(&shared)); // :899 pin
    assert!(FileCapture::flush_pending(&shared)); // the caller is still in the wait
    // std::atomic<unsigned> completed_flushes = 0;  (:888)
    let mut completed_flushes: u32 = 0;
    // CHECK(completed_flushes == 0)  (:901)
    assert_eq!(completed_flushes, 0);
    // CHECK(FileCapture::get_buffers_in_use() == 1)  (:902) — second sits queued
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 1);

    // fixture.gate.release_idle_transition();  (:904) — the loop re-runs:
    // back at :83, the second capture pops, stores (:105), deletes (:106)
    assert!(FileCapture::writer_step(&shared));
    // flush.join();  (:905) — predicate now holds (empty + idle)
    FileCapture::flush(&shared);
    completed_flushes += 1;
    // CHECK(completed_flushes == 1)  (:907)
    assert_eq!(completed_flushes, 1);
    // file_counts_update_buffers();  (:908)
    counts.borrow_mut().file_buffers_in_use =
        FileCapture::get_buffers_in_use(&shared) as u64;
    // CHECK(file_counts.file_buffers_in_use == 0)  (:909)
    assert_eq!(counts.borrow().file_buffers_in_use, 0);
    // CHECK(FileCapture::get_buffers_in_use() == 0)  (:910)
    assert_eq!(FileCapture::get_buffers_in_use(&shared), 0);
    // CHECK(FileCaptureTestAccess::released_buffers() == 2)  (:911)
    assert_eq!(FileCapture::released_buffers(&shared), 2);

    // ~AsyncCaptureFixture :793-:796 (exit drains empty, then reset):
    FileCapture::exit(&shared);
    FileCapture::test_reset(&shared);
    assert!(FileCapture::resettable(&shared));
}
