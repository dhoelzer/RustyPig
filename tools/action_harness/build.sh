#!/usr/bin/env bash
# Ground-truth probe over the ORIGINAL managers/action_manager.cc registry
# statics (get_interface/get_action_string/get_action_type/
# get_max_action_types/get_action_priorities). registry.cc is those five
# functions + their three file-statics copied verbatim (renamed am_*; the
# ActionClass new is stubbed because PluginManager pulls in everything).
# main/policy.cc itself needs DAQ/DataBus/Shell and cannot compile
# hermetically; its three Catch cases are ported directly in
# tests/policy_test.rs against the sources read at fe29cbe.
set -euo pipefail
S=${S:-/opt/data/snort3-src/src}
D=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$D/copy"
cat > "$D/copy/original_api.h" <<'EOF'
#pragma once
#include <cstdint>
#include <string>
namespace snort {
class IpsAction { public: using Type = uint8_t;
  enum IpsActionPriority : uint16_t { IAP_OTHER=1, IAP_LOG=10, IAP_ALERT=20, IAP_REWRITE=30, IAP_DROP=40, IAP_BLOCK=50, IAP_REJECT=60, IAP_PASS=70, IAP_MAX=IAP_PASS };
};
struct BaseApi { const char* name; };
struct ActionApi { BaseApi base; IpsAction::IpsActionPriority priority; };
struct PlugInterface { virtual ~PlugInterface(){} };
}
EOF

python3 - <<PY
import re
src = open('$S/managers/action_manager.cc').read()
header = '''// Verbatim copy of the s_act_types/s_act_priorities/s_act_index statics and
// five ActionManager registry functions from ORIGINAL
// managers/action_manager.cc:95-167 (am_* renames; ActionClass stubbed).
#include <algorithm>
#include <map>
#include <string>
#include <unordered_map>
#include "original_api.h"

using namespace snort;
using namespace std;

using ACTypeList = unordered_map<string, IpsAction::Type>;
using ACPriorityList = map<IpsAction::IpsActionPriority, string, std::greater<int>>;
static ACTypeList s_act_types;
static ACPriorityList s_act_priorities;
static IpsAction::Type s_act_index = 0;

// fwd decl needed because the am_ rename crosses class-member resolution
IpsAction::Type am_get_max_action_types();
'''
parts=[header]
for fn in ['get_interface','get_action_string','get_action_type','get_max_action_types','get_action_priorities']:
    m = re.search(r'(?:PlugInterface\*|std::string|IpsAction::Type)\s+ActionManager::'+fn+r'\([^)]*\)[^{]*\{.*?\n\}', src, re.S)
    assert m, fn
    body = (m.group(0)
            .replace('ActionManager::','am_')
            .replace('return new ActionClass(api);','return new PlugInterface();')
            .replace('return get_max_action_types();','return am_get_max_action_types();'))
    parts.append(body)
open('$D/registry.cc','w').write("\n".join(parts)+"\n")
PY

cat > "$D/probe.cc" <<'EOF'
#include <cstdio>
#include "original_api.h"
using namespace snort;
PlugInterface* am_get_interface(const ActionApi* api);
std::string am_get_action_string(IpsAction::Type a);
IpsAction::Type am_get_action_type(const char* s);
IpsAction::Type am_get_max_action_types();
std::string am_get_action_priorities(bool abp);

static void reg(const char* name, IpsAction::IpsActionPriority p)
{
    ActionApi api{}; api.base.name = name; api.priority = p;
    am_get_interface(&api);
}

int main()
{
    reg("drop", IpsAction::IAP_DROP);
    reg("reject", IpsAction::IAP_REJECT);
    reg("alert", IpsAction::IAP_ALERT);
    reg("log", IpsAction::IAP_LOG);
    reg("pass", IpsAction::IAP_PASS);
    for (int i = 0; i <= (int)am_get_max_action_types(); ++i)
        printf("AS %d %s\n", i, am_get_action_string((IpsAction::Type)i).c_str());
    for (const char* s : {"drop","reject","alert","log","pass","nope",""})
        printf("AT %s %d\n", s, (int)am_get_action_type(s));
    printf("PRI0 [%s]\n", am_get_action_priorities(false).c_str());
    printf("PRI1 [%s]\n", am_get_action_priorities(true).c_str());

    // duplicate registration + duplicate priority quirk
    reg("drop", IpsAction::IAP_DROP);
    reg("custom", IpsAction::IAP_ALERT); // dup priority with alert
    printf("MAX2 %d\n", (int)am_get_max_action_types());
    printf("PRI2 [%s]\n", am_get_action_priorities(false).c_str());
    printf("AS2 0 %s\n", am_get_action_string(0).c_str());
    return 0;
}
EOF

cd "$D"
g++ -std=c++17 -Icopy -c registry.cc -o registry.o
g++ -std=c++17 -Icopy probe.cc registry.o -o probe
./probe > vectors.txt
cat vectors.txt
