// probe_tail.cc — appended to the (merged) original parse_so_rule.cc.
// Tables syntax_tests/basic_tests/stub_tests are file-static in the same TU
// (UNIT_TEST defined), so they are replayed here verbatim. Escape style:
// printable ASCII kept, everything else \xNN (like tools/textlog_harness).
#include <cstdio>
#include <string>

static std::string esc(const std::string& s)
{
    std::string out;
    for (unsigned char c : s)
    {
        if ( c >= 0x20 && c < 0x7f ) out += (char)c;
        else
        {
            char b[8];
            snprintf(b, sizeof(b), "\\x%02x", c);
            out += b;
        }
    }
    return out;
}

static void emit(const char* rule)
{
    SoRuleParser sop;
    std::string stub, opts;
    bool r = sop.parse_so_rule(rule, stub, opts);
    std::printf("IN %s\n", esc(rule).c_str());
    std::printf("R %d STUB [%s] OPTS [%s]\n", r ? 1 : 0,
        esc(stub).c_str(), esc(opts).c_str());
}

static void emit_stub(const char* rule)
{
    std::string stub;
    bool r = get_so_stub(rule, stub);
    std::printf("IN %s\n", esc(rule).c_str());
    std::printf("GETSTUB %d [%s]\n", r ? 1 : 0, esc(stub).c_str());
}

template <size_t N>
static void replay(const ParseSOTestCase (&tbl)[N], bool via_public)
{
    for ( const ParseSOTestCase* tc = tbl; tc->rule; ++tc )
    {
        if ( via_public ) emit_stub(tc->rule);
        else emit(tc->rule);
    }
}

int main()
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    std::printf("=== syntax (full channels) ===\n");
    replay(syntax_tests, false);
    std::printf("=== basic (full channels) ===\n");
    replay(basic_tests, false);
    std::printf("=== stub (full channels) ===\n");
    replay(stub_tests, false);
    std::printf("=== get_so_stub parity ===\n");
    replay(stub_tests, true);

    std::printf("=== extras ===\n");
    // opts channel + trim + prev-space tracking edge cases
    emit("");                       // empty: loop never runs -> false
    emit("alert");                  // never reaches '(' -> false
    emit("alert(");                 // unterminated -> false
    emit("alert(a b id:1 c d; )");  // header before '(' is verbatim-ish
    emit("alert( sid:1;  content:\"x\"; sid:2; )");  // double space + dup sid->opts
    emit("alert( content:\"a\\\\\\\\\"; )");          // escaped backslash in string
    emit("alert( rem:\"unbalanced\" )");            // closing ) inside state 6? string ends then )
    emit("alert( sid:1;\n\tcontent:\"x\"; )");      // newline + tab in options (state>=6 keeps both)
    emit("alert( sid:1; msg:\" a  b \"; )");        // spaces inside quoted preserved
    emit("alert /*x*/ ( flow:to_server; sid:9; )"); // C comment before ( with next=0 path
    emit("alert(#c\nflowbits:set;A; )");           // bash comment inside (, semicolon in opt
    emit("alert( soid:5; );");                     // ) closes before trailing ; -> return at )
    emit("alert( sid:1; /*unterminated )");        // ) inside unterminated comment
    emit("alert( content:\"a;b\"; sid:1 )");       // ; inside quoted must not split opts
    emit("alert(   sid:1;   )");                   // multi-space after ( in state 5
    emit("alert\n(\nsid:1;\n)");                   // newlines outside state>=6 -> single space
    emit("alert( id :0; )");                       // is_stub_option finds "id" via find_first_of -> not stub ("id" not in set) -> opts
    emit("alert( sid :1; )");                      // "sid" IS a stub name even with space before :
    emit("alert( msg; )");                         // bare msg (no colon/space) -> name "msg" stub
    emit("alert( msg:a;b;c )");                    // opts tail after first non-stub: b;c kept raw incl missing ;
    emit("alert( soid; ) # tail after rule");      // returns at ) — trailing text ignored

    std::printf("=== done ===\n");
    return 0;
}
