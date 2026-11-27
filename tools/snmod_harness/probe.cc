// probe.cc — row 24f DEC ladder: construct the REAL SnortModule (the row
// .o) + a REAL SnortConfig (mirror ctor + the REAL SFDAQConfig sub-config)
// and drive set()/begin()/end() over the module's OWN s_params seats
// exactly the way the C flow binds them (Value::set(const Parameter*)),
// then re-read the INLINE seats back (the run/warning/logging flags, the
// SFDAQConfig batch/mru, the ThreadConfig mirror counter, the strings).
// Determinism law: ZERO pointers, ZERO times — names, counts, hex masks
// only. EVERY [[noreturn]]-attributed ground leg is NEVER driven in-proc:
// the c2x/x2c/x2s file-statics exit(0) AND the ENTIRE help_/dump_/list_
// family (main/help.h :34-61, the attribute faces MEASURED). MEASURED law
// at authoring: driving a noreturn-attributed mirror (returning) under
// -O2 makes the else-if chain AFTER it DEAD-CODE-ELIDED — control falls
// through the remaining arms (a 16M-line help_version runaway face); the
// leg family is cited in vectors ONLY through the ABSENT/pfind + witness
// mirror legs the row reaches WITHOUT ever firing one. The dialect legs
// (-j / --shell / --control-socket* SHELL; --exit-after-reload /
// --pause-after-n REG_TEST; --catch-test UNIT_TEST) ride the ABSENT face
// at this posture — pfind prints it, NEVER fires.
#include <cstdio>
#include <cstring>
#include <string>

#include "main/snort_config.h"
#include "main/thread_config.h"
#include "snort_module.h"
#include "framework/value.h"
#include "framework/parameter.h"
#include "packet_io/sfdaq_config.h"
#include "packet_io/trough.h"
#include "trace/trace.h"

using namespace snort;

static SnortModule mod;
static SnortConfig* sc = nullptr;

static const Parameter* pfind(const char* name)
{
    for (const Parameter* p = mod.get_parameters(); p->name; ++p)
        if (!strcmp(p->name, name))
            return p;
    return nullptr;
}

static void leg(const char* name, const char kind, const char* sval, unsigned long long ival)
{
    const Parameter* p = pfind(name);
    if (!p) { printf("L %s ABSENT\n", name); return; }
    Value v((uint64_t)ival);
    if (kind == 's') { v.set(sval); v.set_origin(sval); }
    v.set(p);
    bool r = mod.set(nullptr, v, sc);
    printf("L %s set=%d run_flags=%x out=%x warn=%x batch=%u mru=%d imax=%u\n",
        name, (int)r, (unsigned)sc->run_flags, (unsigned)sc->output_flags,
        (unsigned)SnortConfig::warning_flags,
        sc->daq_config->get_batch_size(), sc->daq_config->get_mru_size(),
        ThreadConfig::get_instance_max());
}

static void dialeg(const char* name) { (void)pfind(name); }

int main()
{
    printf("P0 ctor usage=%d global=%d name=%s help=%s\n",
        (int)mod.get_usage(), (int)mod.global_stats(), mod.get_name(), mod.get_help());
    mod.sum_stats(true);                       // REAL Module::sum_stats (init ladder rides the mirror imax)
    printf("P1 prof0=%s peg0=%s counts=%d gcount=%llu\n",
        []{ const char* n=nullptr; const char* pn=nullptr; return mod.get_profile(0,n,pn) ? n : (const char*)"null"; }(),
        mod.get_pegs() && mod.get_pegs()->name ? mod.get_pegs()->name : "null",
        mod.get_num_counts(), (unsigned long long)mod.get_global_count("local_commands"));

    sc = new SnortConfig();
    printf("K0 conf batch=%u mru=%d uid=%d gid=%d retry=%u\n",
        sc->daq_config->get_batch_size(), sc->daq_config->get_mru_size(),
        sc->user_id, sc->group_id, (unsigned)sc->retry_timeout);

    bool b = mod.begin("snort", 0, sc);
    printf("B1 begin=%d\n", (int)b);

    // ---- the set() ladder ----
    leg("-T", 'i', nullptr, 0);
    leg("-O", 'i', nullptr, 0);
    leg("-q", 'i', nullptr, 0);
    leg("-H", 'i', nullptr, 0);
    leg("-C", 'i', nullptr, 0);
    leg("-d", 'i', nullptr, 0);
    leg("-e", 'i', nullptr, 0);
    leg("-X", 'i', nullptr, 0);
    leg("--pedantic", 'i', nullptr, 0);
    leg("--nostamps", 'i', nullptr, 0);
    leg("--id-subdir", 'i', nullptr, 0);
    printf("ID id_subdir=%d id_zero=%d\n", (int)sc->id_subdir, (int)sc->id_zero);
    leg("--id-zero", 'i', nullptr, 0);
    printf("ID2 id_zero=%d\n", (int)sc->id_zero);
    leg("--dirty-pig", 'i', nullptr, 0);
    leg("--enable-inline-test", 'i', nullptr, 0);
    leg("--nolock-pidfile", 'i', nullptr, 0);
    leg("--show-file-codes", 'i', nullptr, 0);
    leg("--alert-before-pass", 'i', nullptr, 0);
    leg("--no-warn-flowbits", 'i', nullptr, 0);
    leg("--no-warn-rules", 'i', nullptr, 0);
    leg("--close-all-plugins", 'i', nullptr, 0);
    leg("-M", 'i', nullptr, 0);
    leg("-v", 'i', nullptr, 0);
    printf("LG syslog=%d quiet=%d verbose=%d warn=%x\n",
        (int)SnortConfig::log_syslog(), (int)SnortConfig::log_quiet(),
        (int)SnortConfig::log_verbose(), (unsigned)SnortConfig::warning_flags);
    leg("--daq", 's', "pcap", 0);
    printf("DQ mods=%zu name=%s mode=%d vars=%zu\n",
        sc->daq_config->module_configs.size(),
        sc->daq_config->module_configs.empty() ? "none" : sc->daq_config->module_configs[0]->name.c_str(),
        sc->daq_config->module_configs.empty() ? -1 : (int)sc->daq_config->module_configs[0]->mode,
        sc->daq_config->module_configs.empty() ? 0 : sc->daq_config->module_configs[0]->variables.size());
    leg("--daq-mode", 'i', nullptr, 1);
    printf("DQ2 mode=%d\n", (int)sc->daq_config->module_configs[0]->mode);
    leg("--daq-var", 's', "k=v", 0);
    printf("DQ3 vars=%zu kv=%s\n", sc->daq_config->module_configs[0]->variables.size(),
        (sc->daq_config->module_configs[0]->variables[0].first + "=" + sc->daq_config->module_configs[0]->variables[0].second).c_str());
    leg("--daq-batch-size", 'i', nullptr, 37);
    leg("--daq-dir", 's', "a:b", 0);
    printf("DD dirs=%zu\n", sc->daq_config->module_dirs.size());
    leg("--daq-mode", 'i', nullptr, 9);                  // out-of-range switch face (mode UNCHANGED)
    printf("DQ4 mode=%d\n", (int)sc->daq_config->module_configs[0]->mode);
    leg("-z", 'i', nullptr, 4);
    leg("--id-offset", 'i', nullptr, 7);
    leg("-G", 'i', nullptr, 3);
    printf("IO id_offset=%u logid=%u\n", (unsigned)sc->id_offset, (unsigned)sc->event_log_id);
    leg("-s", 'i', nullptr, 300);
    leg("-n", 'i', nullptr, 5);
    leg("--skip", 'i', nullptr, 2);
    printf("PK pkt=%llu skip=%llu mru=%d\n",
        (unsigned long long)sc->pkt_cnt, (unsigned long long)sc->pkt_skip, sc->daq_config->get_mru_size());
    leg("--snaplen", 'i', nullptr, 400);
    leg("--retry-timeout", 'i', nullptr, 2000);
    printf("RT retry=%u\n", (unsigned)sc->retry_timeout);
    leg("--bpf", 's', "inbound", 0);
    leg("--run-prefix", 's', "pfx", 0);
    leg("--metadata-filter", 's', "mf", 0);
    printf("ST bpf=%s pfx=%s mf=%s\n", sc->bpf_filter.c_str(), sc->run_prefix.c_str(), sc->metadata_filter.c_str());
    leg("--talos", 'i', nullptr, 0);
    leg("--pcap-list", 's', "a.pcap b.pcap", 0);
    leg("--pcap-file", 's', "list.f", 0);
    leg("--pcap-dir", 's', "dir", 0);
    leg("--pcap-filter", 's', "flt", 0);
    leg("--pcap-loop", 'i', nullptr, 3);
    leg("--pcap-no-filter", 'i', nullptr, 0);
    printf("PL loop=%u queue=%u read=%d\n", Trough::get_loop_count(), (unsigned)Trough::get_queue_size(),
        (int)sc->pcap_show());
    leg("-c", 's', "snort.lua", 0);            // config_conf (plain void, NOT noreturn)
    leg("--rule", 's', "drop tcp any any", 0); // config_conf via --rule (safe)
    leg("-R", 's', ".rules", 0);               // parser_append_rules 'include ' concat (safe)
    leg("--rule-path", 's', "/rules", 0);      // parser_append_includes (safe)
    leg("-k", 's', "noip", 0);
    leg("--max-procs", 'i', nullptr, 4);
    leg("--create-pidfile", 's', "", 0);
    printf("PF pidfile=%d create=%d\n", sc->pid_filename.empty() ? 0 : (int)sc->pid_filename.c_str()[0], (int)sc->create_pid_file());
    leg("--create-instance-file", 'i', nullptr, 0);
    leg("--stdin-rules", 'i', nullptr, 0);
    printf("SI stdin=%d\n", (int)sc->stdin_rules);
    leg("--dump-builtin-options", 's', "sid:1", 0);   // stub_opts assignment leg (NON-noreturn)
    // ---- the [[noreturn]]-cited family NEVER fired in-proc (the ground
    // heads attribute the ENTIRE help_/dump_/list_ family + help_version:
    // main/help.h :34-61 MEASURED; a returning mirror under -O2 ELIDES the
    // rest of the else-if chain — the authored-face runaway, cited NOT
    // driven; the pfind face proves the rows PRESENT in the table) ----
    {
        static const char* cited[] = { "-h", "-V", "--version", "--help-plugins",
            "--help-options", "--help-signals", "--dump-builtin-rules", "--dump-version" };
        for (const char* n : cited)
            printf("NF %s present=%d noreturn-cited\n", n, pfind(n) ? 1 : 0);
    }
    leg("--dump-config", 's', "all", 0);
    printf("DC dt=%d quiet=%d\n", (int)sc->dump_config_type, (int)SnortConfig::log_quiet());
    leg("--dump-config-text", 'i', nullptr, 0);
    leg("--warn-all", 'i', nullptr, 0);
    leg("--warn-flowbits", 'i', nullptr, 0);
    printf("WA warn=%x\n", (unsigned)SnortConfig::warning_flags);

    // ---- the dialect ABSENT face (parameter rows the posture NEVER builds) ----
    dialeg("-j"); dialeg("--shell"); dialeg("--control-socket"); dialeg("--exit-after-reload");
    dialeg("--pause-after-n"); dialeg("--catch-test");          // pfind prints the ABSENT face
    leg("-j", 'i', nullptr, 0);
    leg("--shell", 'i', nullptr, 0);
    leg("--exit-after-reload", 'i', nullptr, 0);
    leg("--catch-test", 's', "all", 0);

    // ---- the pre-end is()/first-was-consumed face ----
    {
        const Parameter* p = pfind("--pause");
        Value v(true); v.set(p);
        bool r1 = mod.set(nullptr, v, sc);
        Value v2(true); v2.set(p);
        bool r2 = mod.set(nullptr, v2, sc);
        printf("IS pause first=%d repeat=%d run_flags=%x pause=%d\n",
            (int)r1, (int)r2, (unsigned)sc->run_flags, (int)!!(sc->run_flags & RUN_FLAG__PAUSE));
    }

    bool e = mod.end(nullptr, 0, sc);
    printf("E1 end=%d warn=%x (end clears the flowbits+rules WARNING legs)\n",
        (int)e, (unsigned)SnortConfig::warning_flags);

    // ---- the post-end IS face: cli_mode flips -> the consumed-set lookup
    // (the legs ride NON-noreturn rows ONLY: --pause / --show-file-codes
    // were set pre-end (cli_opts holds them -> repeat=false post-end) and
    // --dump-rule-meta was NEVER set (post-end first-set=true)) ----
    {
        const Parameter* p = pfind("--pause");
        Value a(true); a.set(p);
        bool r1 = mod.set(nullptr, a, sc);
        const Parameter* q = pfind("--show-file-codes");
        Value b(true); b.set(q);
        bool r2 = mod.set(nullptr, b, sc);
        const Parameter* q2 = pfind("--dump-rule-meta");
        Value c(true); c.set(q2);
        bool r3 = mod.set(nullptr, c, sc);
        printf("IS2 post pause(repeat)=%d file-codes(repeat)=%d rule-meta(first)=%d run_flags=%x\n",
            (int)r1, (int)r2, (int)r3, (unsigned)sc->run_flags);
    }

    mod.set_trace(nullptr);                    // the row's OWN snort_trace seat
    mod.reset_stats();                         // in_main_thread mirror -> REAL Module::reset_stats
    printf("SM gcount_after_reset=%llu trace_opt0=%s\n",
        (unsigned long long)mod.get_global_count("local_commands"),
        mod.get_trace_options() ? mod.get_trace_options()->name : "null");

    printf("fin=PASS\n");
    delete sc;
    return 0;
}
