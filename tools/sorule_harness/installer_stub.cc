// TestCaseInstaller lives in unit_test.cc upstream; the real body calls
// Catch's REGISTER_TEST_CASE. Replicate it here (same construct the
// upstream unit_test.cc performs) so TEST_CASE registrations in
// parse_so_rule.cc actually land in Catch's session for the gate, and
// link cleanly for the probe (whose main never runs the session).
#include "catch/snort_catch.h"
namespace snort {
TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name)
{ REGISTER_TEST_CASE(fun, name) }
TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name, const char* group)
{ REGISTER_TEST_CASE(fun, name, group) }
}
