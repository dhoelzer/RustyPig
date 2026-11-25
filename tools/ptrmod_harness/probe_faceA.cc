// probe_faceA.cc — row 23g FACE-A (the compile-time/ordinal + cold-member
// census, NEVER faked): the Parameter::Type ordinals (framework/
// parameter.h :44-:66 — PT_BOOL 3 / PT_INT 4 / PT_STRING 8 / PT_ENUM 11 /
// PT_MAX 21) + the module.h Usage ordinal (GLOBAL 0, :216) + the h :41-:45
// PacketTraceOutput ordinals (0/1) + the h :29-:33 PacketTracerConfig POD
// layout (the C++ shape the port's owned-field deviation cites AGAINST:
// sizeof 40, file@8) + the Command/Parameter record widths (module.h :65-
// :74 + parameter.h :67-:71) + the REAL value.cc dispatch cold face
// (value.h :128 is() on the param-null cold leg + the :98 set(param) +
// the get_bool/get_uint8 legs through the SAME sp rows the row .o carries)
// + the Value::ValueType ordinals (value.h :41 VT_BOOL 0 / VT_UNUM 2) +
// the 23f tr.o cold singleton echo (is_active()==0: the s_pkt_trace null
// face the row's D0/D9 legs lean on). O0==O2 byte-ident pinned.
#include "packet_io/packet_tracer_module.h"
#include "packet_io/packet_tracer.h"          // the 23f REUSE home
#include "framework/module.h"
#include "framework/parameter.h"
#include "framework/value.h"

#include <cstdio>
#include <cstddef>

using namespace snort;

int main() {
    printf("A1 ptypes bool=%d int=%d string=%d enum=%d max=%d\n",
           (int)Parameter::PT_BOOL, (int)Parameter::PT_INT,
           (int)Parameter::PT_STRING, (int)Parameter::PT_ENUM,
           (int)Parameter::PT_MAX);
    printf("A2 usage GLOBAL=%d pto console=%d file=%d\n",
           (int)Module::GLOBAL, (int)PacketTracerModule::PACKET_TRACE_CONSOLE,
           (int)PacketTracerModule::PACKET_TRACE_FILE);
    printf("A3 pod sizeof=%llu file@%llu enabled@%llu\n",
           (unsigned long long)sizeof(PacketTracerConfig),
           (unsigned long long)offsetof(PacketTracerConfig, file),
           (unsigned long long)offsetof(PacketTracerConfig, enabled));
    printf("A4 sizeof Parameter=%llu Command=%llu Value=%llu\n",
           (unsigned long long)sizeof(Parameter),
           (unsigned long long)sizeof(Command),
           (unsigned long long)sizeof(Value));
    {
        PacketTracerModule m;
        const Parameter* sp = m.get_parameters();
        Value cold(true);                       // no param yet (the parse face)
        Value v(true);  v.set(sp + 0);
        Value u(static_cast<uint64_t>(7)); u.set(sp + 1);
        printf("A5 cold-is=%d is_enable=%d is_other=%d gb=%d u8=%d vt=%d/%d\n",
               (int)cold.is("enable"), (int)v.is("enable"), (int)v.is("output"),
               (int)v.get_bool(), (int)u.get_uint8(),
               (int)v.get_type(), (int)u.get_type());
    }
    {
        bool act = PacketTracer::is_active();   // the 23f cold singleton face
        printf("A6 tr-cold active=%d\n", (int)act);
    }
    printf("Z-A terminator=0\n");
    fflush(stdout);
    return 0;
}
