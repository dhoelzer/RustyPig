#pragma once
#include <cstdarg>
#include <cstdio>
#include "main/snort_types.h"
namespace snort {
enum WarningGroup { WARN_RULES = 0 };
inline void ParseWarning(WarningGroup, const char* fmt, ...)
{ fprintf(stderr, "PARSE-WARNING: "); va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); fprintf(stderr, "\n"); }
inline void LogMessage(const char* fmt, ...)
{ fprintf(stderr, "LOG: "); va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); fprintf(stderr, "\n"); }
inline void ErrorMessage(const char* fmt, ...)
{ fprintf(stderr, "ERROR: "); va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); fprintf(stderr, "\n"); }
}
