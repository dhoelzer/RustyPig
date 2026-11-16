// Ground-truth probe for ORIGINAL utils/stats/output_json.cc +
// helpers/json_stream.cc (both compiled verbatim). render_json writes
// into an ostringstream; the probe dumps the exact string between JSON
// markers so spacing/escaping pins into vectors.txt.
#include <cstdio>
#include <cstring>
#include <sstream>
#include "utils/stats/output_json.h"
#include "utils/stats/snapshot.h"
#include "helpers/json_stream.h"

using namespace snort;
using namespace snort::stats;

static void dump(const char* tag, const std::string& s)
{
    // len= pins the TRAILING std::endl from JsonStream::close() at
    // level 0 (printf %s would print it invisibly before the <JE>).
    printf("<J>%s<LN>%zu<JJ>%s<JE>\n", tag, s.size(), s.c_str());
}

int main()
{
    // J1: empty snapshot -> root object with empty sections array
    {
        Snapshot snap;
        std::ostringstream oss;
        render_json(oss, snap);
        dump("J1", oss.str());
    }

    // J2: render_counter surfaces: percent key appears when set
    // (unlike the text renderer, which ignores percent); all value
    // type branches of put_value; zero counters skipped by default.
    {
        Snapshot snap;
        Builder b(snap);
        Section& sec = b.section("Summary Statistics");
        Group& grp = Builder::group(sec, "g2");
        Builder::counter(grp, "zero", Value((uint64_t)0));
        Builder::counter(grp, "neg", Value((int64_t)-5));
        Builder::counter(grp, "flag", Value(true));
        Builder::counter(grp, "f", Value(0.25));
        Builder::counter(grp, "pc", Value(std::string("strval")));
        {
            Counter c; c.set_name("pct"); c.value = Value((uint64_t)2);
            c.percent = 33.3;
            grp.counters.push_back(c);
        }
        {
            Counter c; c.set_name("mono"); // monostate -> json null
            grp.counters.push_back(c);
        }
        std::ostringstream oss;
        render_json(oss, snap);
        dump("J2", oss.str());
    }

    // J3: tables: columns array, rows array, per-row put_value
    // (monostate cell -> null). the tables array opens whenever
    // !tables.empty() EVEN IF every table is row-less (filtered per
    // table); group also has a live counter so it is renderable.
    {
        Snapshot snap;
        Builder b(snap);
        Section& sec = b.section("S3");
        Group& grp = Builder::group(sec, "g3");
        Builder::counter(grp, "live", Value((uint64_t)1));
        Table& t = Builder::table(grp, "t", { "name", "v" });
        Builder::row(t, { Value(std::string("row-one")), Value((uint64_t)12) });
        Builder::row(t, { Value(std::string("x-that-is-over-twenty-five-chars-long")),
                          Value(std::string("val")), Value() });
        Builder::row(t, { Value(std::string("solo")) });
        Builder::table(grp, "empty", { "c" });
        std::ostringstream oss;
        render_json(oss, snap);
        dump("J3", oss.str());
    }

    // J4: include_zeros makes an all-zero group renderable; percent key
    // path with zero value + total set.
    {
        Snapshot snap;
        Builder b(snap);
        Section& sec = b.section("S4");
        Group& grp = Builder::group(sec, "z");
        Builder::counter(grp, "zero", Value((uint64_t)0));
        RenderOptions opt{ true };
        std::ostringstream oss;
        render_json(oss, snap, opt);
        dump("J4", oss.str());
    }

    // J5: empty-string counter renders quoted "" via put_string
    // (put_value routes to put_string, NOT the early-returning
    // put(key,std::string)); JsonStream::put(key, std::string) with an
    // empty value early-returns WITHOUT split(); null char* renders
    // null and split() was already consumed.
    {
        Snapshot snap;
        Builder b(snap);
        Section& sec = b.section("S5");
        Group& grp = Builder::group(sec, "g5");
        Builder::counter(grp, "empty", Value(std::string("")));
        std::ostringstream oss;
        render_json(oss, snap);
        dump("J5", oss.str());

        std::ostringstream js;
        {
            JsonStream s(js);
            s.open();
            std::string empty;
            s.put("gone", empty);      // early return: no split, no key
            s.put("still", std::string("here"));
            s.close();
        }
        dump("J5b", js.str());

        std::ostringstream jn;
        {
            JsonStream s(jn);
            s.open();
            s.put("nullptr", (const char*)nullptr);
            s.put("nempty", "");      // char* overload early-returns too
            s.put_true("t");
            s.put_false("f");
            s.close();
        }
        dump("J5c", jn.str());
    }

    // J6: escaping through the stream: specials, control chars,
    // 0x7e/0x7f/0x80 (0x7f printable per C locale isprint on bytes
    // cast to unsigned char; 0x80 -> \u0080)
    {
        std::ostringstream jx;
        {
            JsonStream s(jx);
            s.open();
            const char specials[] = "\" \\ \b \f \n \r \t";
            s.put_string("specials", specials);
            const char ctrl[] = { 0x01, 0x02, 0x03, 0 };
            s.put_string("ctrl", ctrl);
            s.put_string("del", std::string("\x7e\x7f\x80", 3));
            s.close();
        }
        dump("J6", jx.str());
    }

    // J7: separator/levels state machine: close() at level 0 with no
    // open arrays emits std::endl; close_array at level_array 0 with an
    // open object does not; sep resets after the endl.
    {
        std::ostringstream jy;
        {
            JsonStream s(jy);
            s.open();
            s.open_array("a");
            s.open();            // object in array (no key)
            s.uput("n", 1);
            s.close();           // level_array still 1 -> no endl
            s.open();
            s.put("m", (int64_t)-2);
            s.close();
            s.close_array();     // object level still open -> no endl
            s.close();           // level 0, no arrays -> endl
        }
        dump("J7", jy.str());
    }

    // J8: precision stickiness: put(double, precision) sets
    // precision() AND std::fixed on the stream permanently; later
    // doubles use the LAST precision until a new put resets it,
    // integers/strings unaffected.
    {
        std::ostringstream jz;
        {
            JsonStream s(jz);
            s.open();
            s.put("p1", 0.125, 1);
            s.put("p3", 0.125, 3);
            s.put("p2", 0.125, 2);
            s.put("i", (int64_t)7);
            s.put("str", std::string("0.125"));
            s.close();
        }
        dump("J8", jz.str());
    }

    // J9: escape_json_append's str_esc_pos split path: a string whose
    // first char needs no escaping has append(v,pos) then the loop
    // from pos; when pos == 0 the pre-loop append is skipped.
    {
        std::string out;
        escape_json_append(out, "a<b>c", 5);        // no escapes, pos==len
        out.push_back('|');
        escape_json_append(out, "\"q", 2);          // pos==0
        out.push_back('|');
        escape_json_append(out, "pre\tpost", 8);    // pos==3
        out.push_back('|');
        escape_json_append(out, "", 0);             // empty: early return
        printf("<E>%s<EE>\n", out.c_str());
    }

    printf("DONE\n");
    return 0;
}
