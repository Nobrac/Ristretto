#include "filter_fakes.h"
#include <cstring>

namespace rt
{
    std::map<std::pair<std::wstring, std::wstring>, Value> values;
    LSTATUS   getStatus = ERROR_SUCCESS;
    ULONGLONG nowUnix   = 1800000000ull;
    ULONGLONG tickMs    = 1000000ull;

    void Reset()
    {
        values.clear();
        getStatus = ERROR_SUCCESS;
    }
}

LSTATUS RegGetValueW(HKEY root, LPCWSTR subKey, LPCWSTR value, DWORD flags,
                     LPDWORD type, PVOID data, LPDWORD cbData)
{
    (void)type;
    if (root != HKEY_LOCAL_MACHINE || !subKey || !value || !data || !cbData)
        return ERROR_FILE_NOT_FOUND;
    if (rt::getStatus != ERROR_SUCCESS)
        return rt::getStatus;

    auto it = rt::values.find({ subKey, value });
    if (it == rt::values.end())
        return ERROR_FILE_NOT_FOUND;
    if (!(flags & it->second.flag))
        return ERROR_UNSUPPORTED_TYPE;

    const DWORD need = it->second.flag == RRF_RT_REG_QWORD ? 8 : 4;
    if (*cbData < need)
        return ERROR_OUTOFMEMORY;
    if (need == 8)
        std::memcpy(data, &it->second.data, 8);
    else
    {
        const DWORD v = static_cast<DWORD>(it->second.data);
        std::memcpy(data, &v, 4);
    }
    *cbData = need;
    return ERROR_SUCCESS;
}

ULONGLONG GetTickCount64()
{
    return rt::tickMs;
}

void GetSystemTimeAsFileTime(LPFILETIME ft)
{
    const ULONGLONG ticks = rt::nowUnix * 10000000ull + 116444736000000000ull;
    ft->dwLowDateTime  = static_cast<DWORD>(ticks & 0xFFFFFFFFull);
    ft->dwHighDateTime = static_cast<DWORD>(ticks >> 32);
}
