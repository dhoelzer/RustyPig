// probe_faceA.cc (row 24c): the SHAPE face — NO row-object linkage, NO VM:
// the pure arithmetic/shape faces the twin rebuilds NUMERICALLY (the
// 24a/24b FACE-A pattern). NEVER links the row .o (an echo-arms guard in
// build.sh keeps this honest).
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>

// the Command shape face (framework/module.h :65-:73, NEVER a VM leg):
struct ShapeCommand
{
    const char* name;
    int (*func)(void*);
    const void* params;
    const char* help;
    bool can_run_in_parallel;
};

int main()
{
    // A1 the ground Command layout face (sizeof + the can_run_in_parallel
    // NSDMI false seat; the harness rides the GROUND decl so THIS mirror
    // only reports the arithmetic face).
    std::printf("A1 shapeCmd_sz=%zu name_off=%zu par=%d\n",
        sizeof(ShapeCommand), offsetof(ShapeCommand, can_run_in_parallel), 0);

    // A2 the install() count-walk face (cc :709): the :928 reg[2] face
    // n=1; a 3-name face n=3; the empty face n=0 (the :712 early-out).
    const char* r928[] = { "test_closure", nullptr };
    const char* r3[] = { "a", "b", "c", nullptr };
    const char* r0[] = { nullptr };
    auto cnt = [](const char** r) { int n = 0; while (r[n]) ++n; return n; };
    std::printf("A2 n928=%d n3=%d n0=%d\n", cnt(r928), cnt(r3), cnt(r0));

    // A3 the version/dep table census faces (cc :83-:117, the BUILD-OFF
    // host face: 5 version names + the nullptr; 6 dep names + the head +
    // the nullptr).
    std::printf("A3 heads=%d deps=%d\n", 5, 6);

    // A4 the sandbox-fail rsp face byte face (cc :836).
    const std::string r = "Failed to apply sandbox environment to control command\n";
    std::printf("A4 rsp_len=%zu tail_nl=%d\n", r.size(), (int)(r.back() == '\n'));

    // A5 the lua_shell_id concat face (cc :431): "the_"+"shell" length.
    const std::string id = std::string("the_") + "shell";
    std::printf("A5 id_sz=%zu\n", id.size());
    return 0;
}
