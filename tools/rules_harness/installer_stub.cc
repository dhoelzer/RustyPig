#include "catch/snort_catch.h"
namespace snort {
TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name)
{ REGISTER_TEST_CASE(fun, name) }
TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name, const char* group)
{ REGISTER_TEST_CASE(fun, name, group) }
}
