#pragma once
// Values for the APIs the Ristretto filter needs beyond Doppio's fakes
// (extern/doppio/tests/native/lsa_fakes.h): registry values with data, the
// wall clock and the tick count.
#include <windows.h>
#include <map>
#include <string>
#include <utility>

namespace rt
{
    struct Value { DWORD flag; ULONGLONG data; };   // flag: RRF_RT_REG_DWORD or _QWORD

    // (key path, value name) -> typed value, for RegGetValueW.
    extern std::map<std::pair<std::wstring, std::wstring>, Value> values;
    extern LSTATUS getStatus;      // returned by RegGetValueW if not ERROR_SUCCESS

    extern ULONGLONG nowUnix;      // GetSystemTimeAsFileTime
    extern ULONGLONG tickMs;       // GetTickCount64

    void Reset();
}
