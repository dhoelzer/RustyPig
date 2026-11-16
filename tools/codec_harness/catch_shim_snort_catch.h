// Witness Catch header: upstream codec.cc's UNIT_TEST block includes
// catch/snort_catch.h, whose TEST_CASE wrapper needs the snort main-binary
// TestCaseInstaller (global-storage plumbing we don't link). Plain catch.hpp
// gives the SAME four [buffer] TEST_CASE registrations. Logged deviation.
#pragma once
#pragma GCC visibility push(default)
#include "catch/catch.hpp"
#pragma GCC visibility pop
