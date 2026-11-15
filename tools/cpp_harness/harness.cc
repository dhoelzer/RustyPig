#include "ports/port_object.h"
#include "ports/port_utils.h"
#include "ports/port_var_table.h"
#include "parser/parse_ports.h"
#include <cstdio>
using namespace snort;

static void dump(const char* label, PortObject* po)
{
    if (!po) { printf("%s: NULL\n", label); return; }
    printf("%s:", label);
    if (po->item_list) {
        SF_LNODE* pos = nullptr;
        for (PortObjectItem* it = (PortObjectItem*)sflist_first(po->item_list, &pos);
             it; it = (PortObjectItem*)sflist_next(&pos))
            printf(" [%s%u:%u]", it->negate ? "!" : "", it->lport, it->hport);
    }
    printf(" | nc=%ld cnt_any=%d pure_not=%d hp80=%d name=%s h=%u\n",
        (long)PortObjectPortCount(po), PortObjectHasAny(po), PortObjectIsPureNot(po),
        PortObjectHasPort(po, 80), po->name ? po->name : "(null)",
        PortObjectHash(po, 1000, 65536, 7));
}

int main()
{
    const char* cases[] = {
        "any", "80", "80:100", ":100", "100:", "80:", "80,80", "1:2,3:4",
        "!,80", "![80,90]", "[80,90],100:200", "[80]", "100:90", "abc",
        "80,abc", "100:4294967396", "70000", "[80", "80]", "[[80]]", "",
        " ", "\t", ":", "!", "!:", "!0:65535", "!80", "!100:200", "0:65535",
        "80 : 100", "80 , 90", "[80,90]", "1:,3:", "65535", "[89:91]90",
        "80,,90", ":", "21,23,25,443", "1024:65535", "0,80,65535",
        "80\t90", "999999999999999999999", "[80,80]", "8,9,10", "![8,9]",
        "1:2:3", "80:", "!!80", "[!80]", "$FOO",
    };
    for (auto s : cases) {
        POParser pop;
        PortObject* r = PortObjectParseString(nullptr, &pop, nullptr, (char*)s, 0);
        char lab[512];
        snprintf(lab, sizeof(lab), "<%s>", s);
        dump(lab, r);
        printf("  err=%d: %s\n", pop.errflag, PortObjectParseError(&pop));
        if (r) { PortObject* r2 = PortObjectDupPorts(r); dump("dup", r2); PortObjectFree(r2); PortObjectFree(r); }
    }

    // var table flow
    PortVarTable* pvt = PortVarTableCreate();
    POParser pop;
    PortObject* up = PortObjectParseString(pvt, &pop, nullptr, "HTTP_PORTS 80,443", 1);
    dump("var-def", up);
    printf("  err=%d\n", pop.errflag);
    PortVarTableAdd(pvt, up);
    pop.errflag = 0;
    up = PortObjectParseString(pvt, &pop, nullptr, "$HTTP_PORTS,99", 0);
    dump("var-ref", up);
    printf("  err=%d\n", pop.errflag);
    if (up) PortObjectFree(up);
    pop.errflag = 0;
    up = PortObjectParseString(pvt, &pop, nullptr, "$NOPE", 0);
    if (up) PortObjectFree(up);
    printf("<$NOPE>: %s err=%d\n", up ? "OK" : "NULL", pop.errflag);
    PortVarTableFree(pvt);

    // remove_ports: A minus B
    POParser p1, p2;
    PortObject* a = PortObjectParseString(nullptr, &p1, nullptr, "80:90", 0);
    PortObject* b = PortObjectParseString(nullptr, &p2, nullptr, "85:86", 0);
    PortObjectRemovePorts(a, b);
    dump("sub", a);
    PortObjectFree(a);
    PortObjectFree(b);
    return 0;
}
