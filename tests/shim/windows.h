// Test-only <windows.h>: Doppio's shim (extern/doppio/tests/native/shim)
// plus what the Ristretto filter uses on top of it - RegGetValueW, the clock,
// the interlocked operations. The functions are defined in filter_fakes.cpp.
#pragma once
#include_next <windows.h>

typedef int64_t LONG64;

typedef struct _FILETIME { DWORD dwLowDateTime; DWORD dwHighDateTime; } FILETIME, *LPFILETIME;
typedef union _ULARGE_INTEGER
{
    struct { DWORD LowPart; DWORD HighPart; };
    ULONGLONG QuadPart;
} ULARGE_INTEGER;

#define RRF_RT_REG_DWORD       0x00000010
#define RRF_RT_REG_QWORD       0x00000040
#define ERROR_UNSUPPORTED_TYPE 1630L

LSTATUS   RegGetValueW(HKEY root, LPCWSTR subKey, LPCWSTR value, DWORD flags,
                       LPDWORD type, PVOID data, LPDWORD cbData);
ULONGLONG GetTickCount64();
void      GetSystemTimeAsFileTime(LPFILETIME ft);

inline LONG64 InterlockedCompareExchange64(volatile LONG64* dest, LONG64 exchange, LONG64 comparand)
{
    __atomic_compare_exchange_n(dest, &comparand, exchange, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return comparand;                       // the initial value, as on Windows
}

inline LONG InterlockedCompareExchange(volatile LONG* dest, LONG exchange, LONG comparand)
{
    __atomic_compare_exchange_n(dest, &comparand, exchange, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return comparand;
}

inline LONG InterlockedExchange(volatile LONG* target, LONG value)
{
    return __atomic_exchange_n(target, value, __ATOMIC_SEQ_CST);
}
