// row 23h DEC probe: drives the REAL row .o (the packet_io active pair,
// THE one home) deterministically through the mirror/capture faces declared
// in witness_active.h. ZERO-gate row: NO gates here. The tracer legs ride
// the 23f-kin REAL body (fresh cp + cmp): the trace-log captures read back
// through the REAL PacketTracer::dump face. Everything deterministic:
// counters, ordinals, hex flag faces, captured bytes; never time/random/fs
// (except /dev/null dup2 around the two FatalError legs so DEC stderr
// STAYS SILENT).
#include "packet_io/active.h"            // THE row .h (donor OVERWRITE face)
#include "packet_io/active_counts.h"    // the REAL get_active_counts face
#include "packet_io/active_action.h"    // the base DECL (inline vtable home)
#include "packet_io/packet_tracer.h"    // the 23f-kin REAL body (tr.o)
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq_module.h"     // the DAQStats extern (def = witness)
#include "main/policy.h"
#include "main/snort_config.h"
#include "detection/ips_context.h"
#include "flow/flow.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/ipv4.h"

#include "witness_active.h"

#include <csetjmp>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

// THE 23c noreturn RIDER jump sites (owned by the carried EXTRACTION):
extern sigjmp_buf fatal_jump;
extern bool fatal_jump_armed;

using namespace snort;

static char pk_store[sizeof(Packet)];
static char ctx_store[sizeof(IpsContext)];
static char flow_store[sizeof(Flow)];
static uint8_t v4buf[20];
static tcp::TCPHdr tcph_buf;
static DAQ_PktHdr_t pkth_buf;

static Active a;                 // the DEC subject Active (row .o methods)
static Packet* p = nullptr;      // the packet skeleton
static ActiveAction* qslot = nullptr;

class ProbeAction : public ActiveAction
{
public:
    int id; int* hits;
    ProbeAction(int prio, int i, int* h) : ActiveAction((ActionPriority)prio), id(i), hits(h) { }
    void delayed_exec(Packet*) override { hits[id]++; }
};
static int pa_hits[4];
static ProbeAction* g_pa_lo = nullptr;
static SFDAQInstance* g_hold_inst = nullptr;
static SFDAQInstance* g_local_inst = nullptr;

static Packet* fresh_packet()
{
    memset(pk_store, 0, sizeof pk_store);
    memset(ctx_store, 0, sizeof ctx_store);
    memset(&pkth_buf, 0, sizeof pkth_buf);
    memset(&tcph_buf, 0, sizeof tcph_buf);
    tcph_buf.th_win = htons(4660);          // Strafe default arm: 4660>>1 = 2330
    p = (Packet*)pk_store;
    p->action = &p->action_inst;
    p->context = (IpsContext*)ctx_store;
    p->context->conf = SnortConfig::get_conf();
    p->pkth = &pkth_buf;
    p->ptrs.tcph = &tcph_buf;
    p->dsize = 100;
    p->ptrs.set_pkt_type(PktType::TCP);
    p->active = &a;
    return p;
}

static void tracer_live()
{
    // the ip-path activate face -> PacketTracer::is_active() TRUE
    memset(v4buf, 0, sizeof v4buf);
    v4buf[0] = 0x45; v4buf[1] = 0;
    p->ptrs.ip_api.set((const ip::IP4Hdr*)v4buf);
    PacketTracer::activate(*p);
}

int main()
{
    p = fresh_packet();

    // ---- the tracer REAL body LIVE (configure BEFORE thread_init: the
    // ctor picks up config_status; log "-" -> log_fh = stdout (no file))
    PacketTracer::configure(true, "-");
    PacketTracer::thread_init();
    tracer_live();
    printf("Q0 packet_tracer_active=%d sl=[%s]\n", (int)PacketTracer::is_active(), sl_capture);

    // ---- T0: the COLD identity face of a fresh Active THROUGH the row .o
    printf("T0 cold st=%d whd=%d act=%d delay=%d bypass=%d dr=%d\n",
        (int)a.get_status(), (int)a.get_would_be_dropped_reason(),
        (int)a.get_action(), (int)a.get_delayed_action(),
        (int)a.get_tunnel_bypass(), a.get_drop_reason() ? 1 : 0);
    a.reset();

    // ---- T1: the act_str TABLE readout (row-owned static THROUGH the
    // real getters): 8 action rows x 4 status cols. Status faces:
    // ALLOW=reset default; CANT=suspend+update; WOULD=suspend+update x2;
    // FORCE=update(force). The pure-inline setters never touch status.
    {
        const char* rows[8];
        for (int st = 0; st < 4; st++) {
            for (int act = 0; act < 8; act++) {
                a.reset();
                switch (act) {
                case 0: a.set_trust(); break;                       // ACT_TRUST (pure setter)
                case 1: a.set_allow(); break;                       // ACT_ALLOW (pure setter)
                case 2: { if (!g_hold_inst) g_hold_inst = new SFDAQInstance(nullptr, 0, nullptr);
                          p->daq_instance = g_hold_inst; a.hold_packet(p); } break;  // -> ACT_HOLD (pool 8 >= batch 4) — ONE pinned instance (D14 counting face)
                case 3: p->daq_instance = nullptr; if (!g_local_inst) g_local_inst = new SFDAQInstance(nullptr, 0, nullptr);
                        sfd_local = g_local_inst;
                        a.retry_packet(p); break;                   // -> ACT_RETRY (SFDAQ::get_local_instance leg)
                case 4: a.rewrite_packet(p); break;                 // -> ACT_REWRITE
                case 5: a.drop_packet(p); break;                    // -> ACT_DROP
                case 6: a.block_again(); break;                     // ACT_BLOCK (pure setter)
                case 7: a.reset_again(); break;                     // ACT_RESET (pure setter)
                }
                // stamp the status WITHOUT touching the action:
                switch (st) {
                case 0: break;                             // ALLOW (reset default)
                case 1: Active::suspend(Active::ASP_NONE); a.update_status(p); break;
                case 2: Active::suspend(Active::ASP_NONE); a.update_status(p); a.update_status(p); break;
                case 3: a.update_status(p, true); break;
                }
                rows[act] = a.get_action_string();
                Active::resume();
            }
            char line[512];
            snprintf(line, sizeof line, "row%d %s|%s|%s|%s|%s|%s|%s|%s", st,
                rows[0], rows[1], rows[2], rows[3], rows[4], rows[5], rows[6], rows[7]);
            printf("T1 %s\n", line);
        }
        p->daq_instance = nullptr; sfd_local = nullptr;
    }

    // ---- T2: the counters all-zero cold face via the REAL
    // get_active_counts() walk (7 PegCounts)
    {
        PegCount* c = get_active_counts();
        printf("T2 c7=%d,%d,%d,%d,%d,%d,%d\n", c[0]!=0, c[1]!=0, c[2]!=0, c[3]!=0, c[4]!=0, c[5]!=0, c[6]!=0);
    }

    // ---- D0: thread_init clamp ladder (25 -> 20 cap; 0 -> 1 floor) + the
    // attempts face through the send_reset loop encode-count.
    {
        SnortConfig sc("");
        sc.respond_attempts = 25;
        Active::thread_init(&sc);
        act_wr_reset_captures();
        a.reset(); a.send_reset(p, 0);
        int clamp20 = pm_encode_calls;
        sc.respond_attempts = 0;
        Active::thread_init(&sc);
        act_wr_reset_captures();
        a.send_reset(p, 0);
        printf("D0 clamp20=%d floor1=%d\n", clamp20, pm_encode_calls);
        (void)clamp20;
    }

    // ---- D1: suspend/resume/is_suspended + the FULL ASP_*->WHD_* map walk
    // (update_status in MAX policy = actionable no-op; the stamp rides
    // cant_drop) + the ActiveSuspendContext RAII face.
    act_wr_set_policy_mode(POLICY_MODE__MAX);
    {
        const uint8_t rs[5] = { 0, 1, 2, 3, 4 };   // ASP_NONE..ASP_EXIT ordinals
        for (int i = 0; i < 5; i++) {
            a.reset();
            Active::suspend((Active::ActiveSuspendReason)rs[i]);
            int in = (int)Active::is_suspended();
            a.update_status(p);
            printf("D1r%d asr=%d susp=%d st=%d whd=%d\n", i, rs[i], in,
                (int)a.get_status(), (int)a.get_would_be_dropped_reason());
            Active::resume();
        }
        printf("D1 after-resume susp=%d whd_none-after=%d\n", (int)Active::is_suspended(),
            (int)Active::get_whd_reason_from_suspend_reason());
        { ActiveSuspendContext c(Active::ASP_RELOAD);
          printf("D1 raii in=%d", (int)Active::is_suspended()); }
        printf(" out=%d\n", (int)Active::is_suspended());
    }

    // ---- D2: can_partial_block_session / keep_pruned_flow /
    // keep_timedout_flow arms (AST_CANT via suspend+cant_drop; the
    // s_suspend_reason >ASP_NONE !=ASP_TIMEOUT arms).
    {
        int cp[4]={0,0,0,0}, kp[4]={0,0,0,0}, kt[4]={0,0,0,0};
        const uint8_t cs[4] = { 0, 1, 2, 3 };      // NONE, PRUNE, TIMEOUT, RELOAD
        for (int i = 0; i < 4; i++) {
            a.reset();
            Active::suspend((Active::ActiveSuspendReason)cs[i]);
            a.update_status(p);
            cp[i] = (int)a.can_partial_block_session();
            kp[i] = (int)a.keep_pruned_flow();
            kt[i] = (int)a.keep_timedout_flow();
            Active::resume();
        }
        printf("D2 st=%d cp=%d,%d,%d,%d kp=%d,%d,%d,%d kt=%d,%d,%d,%d\n",
            (int)Active::AST_CANT, cp[0],cp[1],cp[2],cp[3], kp[0],kp[1],kp[2],kp[3], kt[0],kt[1],kt[2],kt[3]);
    }

    // ---- D3: the cant_drop ALLOW->CANT escalation face + the WOULD face
    // (the MEASURED honest law: update_status calls cant_drop ONLY while
    // status==ALLOW; cant_drop's CANT->WOULD else-arm is DEAD through the
    // public face — the WOULD status lands via the actionable legs at D4).
    // + update_status(force) vs the daq_update_status no-force face.
    {
        a.reset();
        Active::suspend(Active::ASP_EXIT);
        a.update_status(p);            int s1 = (int)a.get_status();   // ALLOW->CANT
        int s1r = (int)a.get_would_be_dropped_reason();
        a.drop_packet(p);              int s2 = (int)a.get_status();   // CANT STAYS (the dead-arm face)
        Active::resume();
        a.reset(); a.update_status(p, true);        int s4 = (int)a.get_status(); // FORCE
        a.reset(); a.daq_drop_packet(p);            int s5 = (int)a.get_status(); // daq arm (MAX-mode no-op)
        printf("D3 cant=%d,%d stay=%d force=%d daq=%d act=%d\n",
            s1, s1r, s2, s4, s5, (int)a.get_action());
    }

    // ---- D4: the actionability arms with the conf mode bits (the
    // ips_inline_test / passive / inline-no-forward / rewrite-no-replace
    // faces -> the WHD_* pins).
    {
        a.reset();
        act_wr_set_policy_mode(POLICY_MODE__INLINE_TEST);
        a.update_status(p);
        int t1 = (int)a.get_status(), t2 = (int)a.get_would_be_dropped_reason();
        act_wr_set_policy_mode(POLICY_MODE__PASSIVE);
        a.reset(); a.update_status(p);
        int p1 = (int)a.get_status(), p2 = (int)a.get_would_be_dropped_reason();
        act_wr_set_policy_mode(POLICY_MODE__INLINE);
        sfd_forwarding = false;
        a.reset(); a.update_status(p);
        int i1 = (int)a.get_status(), i2 = (int)a.get_would_be_dropped_reason();
        sfd_forwarding = true; sfd_can_replace = false;
        a.reset(); a.rewrite_packet(p);   // ACT_REWRITE set; the actionable leg STAMPS (the non-force path)
        int r1 = (int)a.get_status(), r2 = (int)a.get_would_be_dropped_reason();
        // the force-into-FORCE-arm stays face (FORCE skips actionable):
        a.reset(); a.update_status(p, true);
        a.rewrite_packet(p);
        int f1 = (int)a.get_status();
        sfd_can_replace = true;
        act_wr_set_policy_mode(POLICY_MODE__MAX);
        printf("D4 test=%d,%d passive=%d,%d inlineNF=%d,%d rewriteNR=%d,%d forceStay=%d\n",
            t1,t2, p1,p2, i1,i2, r1,r2, f1);
    }

    // ---- D5: the STRAFE ladder (the heart face): attempts=6, a FRESH
    // Active send_reset walk i=0..5; the mirror captures every
    // (TcpResponse kind, EncodeFlags) pair.
    {
        SnortConfig sc("");
        sc.respond_attempts = 6;
        Active::thread_init(&sc);
        act_wr_set_policy_mode(POLICY_MODE__MAX);
        a.reset();
        act_wr_reset_captures();
        a.send_reset(p, 0);
        printf("D5 n=%d kinds=%d,%d,%d,%d,%d,%d\n", pm_encode_calls,
            pm_encode_kind[0],pm_encode_kind[1],pm_encode_kind[2],
            pm_encode_kind[3],pm_encode_kind[4],pm_encode_kind[5]);
        for (int i = 0; i < 6; i++)
            printf("D5f%d=%016llx\n", i, (unsigned long long)pm_flags_seen[i]);
        printf("D5 inj=%d revs=%d len=%d\n", sfd_inject_calls, sfd_inject_rev, sfd_inject_len);
    }

    // ---- D6: set_delayed_action NO-DOWNGRADE law (>= & >ACT_ALLOW arms +
    // the allow->trust exception) + apply_delayed_action switch arms:
    // DROP, BLOCK (force Stream face), RESET (assert+Stream+queue drain),
    // RETRY (null-pool downgrade face), TRUST (cold null-flow face),
    // ALLOW noop, then the delayed=ACT_ALLOW reset face.
    {
        a.reset();
        a.set_delayed_action(Active::ACT_BLOCK);
        int d1 = a.get_delayed_action();
        a.set_delayed_action(Active::ACT_DROP);            // refused (BLOCK(6) >= DROP(5) > ALLOW)
        int d2 = a.get_delayed_action();
        a.reset();
        a.set_delayed_action(Active::ACT_ALLOW);           // delayed ALLOW
        a.set_delayed_action(Active::ACT_TRUST);           // the 1>=0 but !(1>ALLOW) EXCEPTION arm
        int d3 = a.get_delayed_action();
        // DROP arm:
        a.reset(); a.set_delayed_action(Active::ACT_DROP);
        a.apply_delayed_action(p);
        int d4 = (int)a.get_action();
        // BLOCK arm (force not set; MAX policy => NO Stream::block_flow leg):
        a.reset(); a.set_delayed_action(Active::ACT_BLOCK);
        act_wr_reset_captures();
        a.apply_delayed_action(p);
        printf("D6 d=%d,%d trust1=%d drop=%d block=%d sfq=%d\n",
            d1, d2, d3, d4, (int)a.get_action(), stream_block_calls);
        // RESET arm (delayed_reject = the row .o's default_reset via the
        // 1-arg setter): Stream::drop_flow + the QUEUE drain face — the
        // row ResetAction::delayed_exec -> kill_session -> send_reset x2
        // (0 and ENC_FLAG_FWD) THROUGH the encode mirror:
        act_wr_set_policy_mode(POLICY_MODE__MAX);
        a.reset(); a.set_delayed_action(Active::ACT_RESET);
        act_wr_reset_captures();
        a.apply_delayed_action(p);
        int sf_calls = sfd_inject_calls;
        int dropf = stream_drop_calls, initar = stream_init_ar_calls;
        Active::execute(p);                            // the queue drain face
        a.reset();
        // RETRY null-pool downgrade face (pool 1 < batch 4):
        wsi_pool = 1; wsi_batch = 4;
        a.reset(); a.set_delayed_action(Active::ACT_RETRY);
        uint64_t rd_before = daq_stats.retries_dropped;
        a.apply_delayed_action(p);
        printf("D6 reset_act=%d drop_flow=%d init_ar=%d exec_inj=%d retry->drop=%d rd=%llu\n",
            (int)Active::ACT_RESET, dropf, initar, sf_calls,
            (int)a.get_action(), (unsigned long long)(daq_stats.retries_dropped - rd_before));
        wsi_pool = 8; wsi_batch = 4;
        // TRUST cold face (null flow, not force: disable_all capture only):
        a.reset(); a.set_delayed_action(Active::ACT_TRUST);
        act_wr_reset_captures();
        a.apply_delayed_action(p);
        int dee = de_disable_all_calls;
        // ALLOW noop + the reset face:
        int d5 = (int)a.get_delayed_action();
        printf("D6 trust de=%d act=%d delayed_after_apply=%d\n", dee, (int)a.get_action(), d5);
    }

    // ---- D7: trust_session force face + the hold ladder through the REAL
    // 7-slot get_active_counts() readout (holds_denied null-pool +
    // holds_allowed pool + holds_canceled via cancel_packet_hold).
    {
        PegCount* c = get_active_counts();
        uint64_t* v = (uint64_t*)c;
        uint64_t base[7]; for (int i = 0; i < 7; i++) base[i] = v[i];
        p->daq_instance = nullptr; p->packet_flags = 0;
        a.reset();
        a.trust_session(p, true);                       // force: PKT_IGNORE + disable_inspect
        int ign = (int)((p->packet_flags & PKT_IGNORE) != 0);
        int di = (int)p->disable_inspect;
        a.reset(); a.hold_packet(p);                    // DENIED (null-pool face)
        int hd = (int)(v[4] - base[4]);
        SFDAQInstance* si = new SFDAQInstance(nullptr, 0, nullptr);
        p->daq_instance = si;
        a.reset();
        int hr = a.hold_packet(p);                      // ALLOWED face
        int ishold = (int)a.is_packet_held();
        a.cancel_packet_hold();                         // holds_canceled + ACT_ALLOW
        int hc = (int)(v[5] - base[5]);
        a.reset();
        a.trust_session(p, false);                      // null flow: no ACT_TRUST (try_trust never runs)
        int st0 = (int)a.session_was_trusted();
        printf("D7 ig=%d di=%d denied=%d hold=%d ishold=%d can=%d trusted=%d\n",
            ign, di, hd, hr, ishold, hc, st0);
    }

    // ---- D8: the trace-log CAPTURE legs through the REAL tracer: the
    // send_reset encode-fail arm (failed_injects++ + the log line through
    // PacketTracer::dump) + the send_ok line.
    {
        pm_encode_return_null = 1;
        act_wr_reset_captures();
        tracer_live();
        SnortConfig sc(""); sc.respond_attempts = 1;      // ONE attempt: ONE log line per leg (the dump-face pin)
        Active::thread_init(&sc);
        char tb[512];
        PacketTracer::dump(tb, sizeof tb - 1);            // the PRE-LEG flush: discard the D4-D6 carry (the dump FLUSH+RESET face, bytes NEVER printed)
        a.reset(); a.send_reset(p, ENC_FLAG_FWD);         // the encode-FAIL leg
        tb[0] = 0;
        PacketTracer::dump(tb, sizeof tb - 1);            // the flush-and-reset face ONCE (exactly this leg's line)
        printf("D8 fail_log=[%s]\n", tb);
        pm_encode_return_null = 0;
        act_wr_reset_captures();
        a.reset(); a.send_reset(p, ENC_FLAG_FWD);         // the send-OK leg
        tb[0] = 0; PacketTracer::dump(tb, sizeof tb - 1);
        a.reset();
        printf("D8 ok_log=[%s] inj=%d\n", tb, sfd_inject_calls);
        SnortConfig sc2(""); sc2.respond_attempts = 2;
        Active::thread_init(&sc2);
    }

    // ---- D9: send_data loop faces: maxPayload 0 (encode_get_max_payload
    // mirror) => payload loop SKIPPED + the FIN leg success sent++ face;
    // then the FIN encode-FAIL arm failed_injects++ + sent=0.
    {
        pm_maxpayload_face = 0;
        act_wr_reset_captures();
        static const uint8_t pay[7] = { 'p','a','y','l','o','a','d' };
        uint32_t sent = a.send_data(p, ENC_FLAG_FWD, pay, 7);
        int fin_kind = pm_encode_kind[0];
        PegCount* v = (PegCount*)get_active_counts();
        uint64_t f0 = v[1];
        pm_encode_return_null = 1;
        uint32_t sent2 = a.send_data(p, ENC_FLAG_FWD, pay, 7);
        int faildelta = (int)(v[1] - f0);        // the FIN encode-FAIL failed_injects leg
        pm_encode_return_null = 0;
        pm_maxpayload_face = 2;
        uint32_t sent3 = a.send_data(p, ENC_FLAG_FWD, pay, 7);   // the loop-chunked face (2+2+2+1)
        pm_maxpayload_face = 0;
        int loopenc = pm_encode_calls;
        a.reset();
        printf("D9 sent=%d kind=%d maxp=%d sent2=%d fdelta=%d sent3=%d enc=%d\n",
            (int)sent, fin_kind, pm_maxpay_calls, (int)sent2, faildelta, (int)sent3, loopenc);
    }

    // ---- D10: inject_data cold s_attempts=0 early-out face THROUGH the
    // read_mode thread_init face (ParseWarning capture + s_attempts=0).
    {
        SnortConfig sc("");
        sc.run_flags |= RUN_FLAG__READ;                  // the read_mode face
        sc.respond_attempts = 3;
        sfd_can_inject = false;                          // the disabled-face fuel
        bool ok = Active::thread_init(&sc);
        char pw[256]; snprintf(pw, sizeof pw, "%s", pw_buf);
        int pwc = pw_calls;                              // snapshot BEFORE the capture reset (the readout face)
        static const uint8_t pay[4] = { 1,2,3,4 };
        act_wr_reset_captures();
        a.reset(); a.inject_data(p, 0, pay, 4);
        PegCount* v = (PegCount*)get_active_counts();
        uint64_t i0 = v[0], f0 = v[1];
        a.reset();
        printf("D10 rc=%d pwc=%d pw=[%s] inj_calls=%d enc_calls=%d inj_d=%d fail_d=%d\n",
            (int)ok, pwc, pw, sfd_inject_calls, pm_encode_calls,
            (int)(v[0]-i0), (int)(v[1]-f0));
        sfd_can_inject = true;
        SnortConfig sc2(""); sc2.respond_attempts = 2;
        Active::thread_init(&sc2);                       // restore (open NOT taken)
    }

    // ---- D11: the drop_reason faces: cold get_drop_reason_id -1 +
    // map hit + default; set first-wins + the suspended-refused arm;
    // send_reason_to_daq null face + the !==-1 capture through the mirror.
    {
        a.reset();
        int idm1 = -1;                                    // cold face: run get via a probe-Active? private. Face via send_reason_to_daq:
        act_wr_reset_captures();
        p->daq_instance = new SFDAQInstance(nullptr, 0, nullptr);
        p->daq_msg = (DAQ_Msg_h)0x1;                      // opaque sentinel
        a.send_reason_to_daq(*p);                         // null drop_reason early-out
        int e0 = wsi_vp_calls;
        Active::set_default_drop_reason(5);
        a.set_drop_reason("gen-reason");                  // first-wins arm #1
        a.set_drop_reason("late-reason");                 // refused (already set)
        a.send_reason_to_daq(*p);                         // default 5 face
        int d5 = wsi_last_vp_reason;
        Active::map_drop_reason_id("gen-reason", 7);      // map-hit arm
        a.reset(); a.set_drop_reason("gen-reason");
        a.send_reason_to_daq(*p);
        int m7 = wsi_last_vp_reason;
        const char* first = a.get_drop_reason();
        Active::suspend(Active::ASP_EXIT);
        a.reset();                                        // reset CLEARS drop_reason
        a.set_drop_reason("susp-late");                   // suspended-refused arm
        const char* sr = a.get_drop_reason();
        char firstb[32]; snprintf(firstb, sizeof firstb, "%s", first);
        Active::resume();
        a.reset();
        printf("D11 nulleg=%d first=[%s] def5=%d map7=%d suspset=%d\n",
            e0, firstb, d5, m7, sr ? 1 : 0);
        (void)idm1;
    }

    // ---- D12: the queue()/execute() priority law (a->get_action() >
    // (*p->action)->get_action()) + clear_queue + the execute null drain.
    {
        a.reset();
        ProbeAction pa_lo(AP_LOCAL, 0, pa_hits), pa_hi(AP_REMOTE, 1, pa_hits),
                    pa_eq(AP_REMOTE, 2, pa_hits);
        g_pa_lo = &pa_lo;
        *p->action = nullptr;
        Active::queue(&pa_lo, p);                          // empty slot take
        int took1 = (int)(*p->action == &pa_lo);
        Active::queue(&pa_hi, p);                          // 4 > 0 override
        int over = (int)(*p->action == &pa_hi);
        Active::queue(&pa_eq, p);                          // 4 > 4 FALSE arm
        int keep = (int)(*p->action == &pa_hi);
        p->flow = (Flow*)flow_store;
        a.set_trust();                                     // the execute trust round-trip
        act_wr_reset_captures();
        a.queue(&pa_hi, p);
        Active::execute(p);                                        // drain + finalize_trust + Flow::trust capture
        int h1 = pa_hits[1], ft = flow_trust_calls;
        Active::clear_queue(p);
        int clr = (int)(*p->action == nullptr) + de_clear_replacement_calls;
        Active::execute(p);                                        // null-action drain face
        p->flow = nullptr;
        printf("D12 take=%d over=%d keep=%d drain=%d ftrust=%d clr=%d\n",
            took1, over, keep, h1, ft, clr);
    }

    // ---- D13: the reset() CLEARS-7 face after dirtying every field.
    {
        a.set_trust(); a.update_status(p, true); a.set_tunnel_bypass(); a.set_tunnel_bypass();
        a.set_delayed_action(Active::ACT_RESET, g_pa_lo);
        a.set_drop_reason("dirty");
        int pre = (int)(a.get_tunnel_bypass() && a.get_action()==Active::ACT_TRUST
            && a.packet_force_dropped() && a.get_delayed_action()==Active::ACT_RESET
            && a.get_drop_reason()!=nullptr);
        a.reset();
        printf("D13 pre=%d post st=%d whd=%d act=%d delay=%d bypass=%d dr=%d str=[%s]\n",
            pre, (int)a.get_status(), (int)a.get_would_be_dropped_reason(),
            (int)a.get_action(), (int)a.get_delayed_action(),
            (int)a.get_tunnel_bypass(), a.get_drop_reason()?1:0, a.get_action_string());
    }

    // ---- D14: THE dnet/open()/close() ladder + the two FatalError legs
    // (the 23c rider jump, stderr shunted to /dev/null so DEC STAYS
    // SILENT; the jumped-out thread_init side effects stay pinned).
    {
        SnortConfig sc(""); sc.respond_attempts = 2;
        // (a) the ip open-success capture face:
        sfd_can_inject = false;                            // forces the open() leg
        Active::thread_init(&sc);                          // respond_device empty -> ip face
        a.reset(); a.send_reset(p, 0);                     // s_send == send_ip face
        printf("D14 ip_open=%d ip_send=%d eth_open=%d close1=", ip_open_calls, ip_send_calls, eth_open_calls);
        Active::thread_term();                             // ip_close + null-set
        Active::thread_term();                             // the idempotence face (2nd close = no-op)
        printf("%d,%d\n", ip_close_calls, eth_close_calls);
        sfd_can_inject = true;
    }
    {
        SnortConfig sc(""); sc.respond_attempts = 2; sc.respond_device = "eth0";
        sfd_can_inject = true;
        Active::thread_init(&sc);                          // the eth open-success face
        a.reset(); a.send_reset(p, 0);                     // send_eth capture face
        printf("D14h eth_open=%d eth_send=%d\n", eth_open_calls, eth_send_calls);
        Active::thread_term();
    }
    {
        SnortConfig sc(""); sc.respond_attempts = 3; sc.respond_device = "bogus-dev";
        sfd_can_inject = true; dnet_eth_open_fail = 1;
        fflush(stdout);
        int devnull = open("/dev/null", O_WRONLY); int saved2 = dup(2); dup2(devnull, 2);
        int jumped = 0;
        if (sigsetjmp(fatal_jump, 1) == 0) {
            fatal_jump_armed = true;
            Active::thread_init(&sc);                      // FatalError -> siglongjmp
        } else { jumped = 1; }
        dup2(saved2, 2); close(saved2); close(devnull);
        dnet_eth_open_fail = 0;
        printf("D14f eth_fail jumped=%d eth_open=%d eth_close=%d\n", jumped, eth_open_calls, eth_close_calls);
        // the ip-open-fail FatalError face (respond_device empty, can_inject false):
        sfd_can_inject = false; dnet_ip_open_fail = 1;
        SnortConfig sc2(""); sc2.respond_attempts = 3;
        fflush(stdout);
        devnull = open("/dev/null", O_WRONLY); saved2 = dup(2); dup2(devnull, 2);
        jumped = 0;
        if (sigsetjmp(fatal_jump, 1) == 0) {
            fatal_jump_armed = true;
            Active::thread_init(&sc2);
        } else { jumped = 1; }
        dup2(saved2, 2); close(saved2); close(devnull);
        dnet_ip_open_fail = 0; sfd_can_inject = true;
        SnortConfig sc3(""); sc3.respond_attempts = 2;     // restore a clean world
        Active::thread_init(&sc3);
        printf("D14g ipfail jumped=%d ip_open=%d ip_close=%d\n", jumped, ip_open_calls, ip_close_calls);
    }

    // ---- Z: the terminator face.
    PacketTracer::thread_term();
    printf("Z end=0\n");
    return 0;
}
