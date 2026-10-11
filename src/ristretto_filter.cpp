// RistrettoFilter - standalone MSV1_0 sub-authentication FILTER (Auth0).
//
// Companion to Doppio (github.com/Nobrac/Doppio), not a patch. It reads
// Doppio's RID enrollment index (HKLM\SOFTWARE\TheAdminCafe\2FA\Rids) and
// nothing else of Doppio's. While installed it takes over the Auth0 slot
// from TacSubAuth (the installer saves and restores it).
//
// Policy: a NETWORK logon for an enrolled local account needs a fresh gate
// timestamp (HKLM\SOFTWARE\TheAdminCafe\Ristretto\Gate\<rid>, written by
// ristretto.exe after a TOTP check). No fresh gate -> veto, which is exactly
// what TacSubAuth would have done anyway. Everything else: no objection.
//
// Same rules as Doppio's filter: runs in lsass, no heap, fixed buffers, one
// registry read per decision, no DPAPI, no LSA lookups, never touches
// credential material. Test-VM code: unsigned, needs RunAsPPL off.
//
// The RID-index read below duplicates tac::IsEnrolledByRid (store.cpp) on
// purpose. store.cpp cannot be linked into lsass: it also carries
// CryptUnprotectData and LookupAccountName/Sid, which store.cpp's own
// comments ban from the LSA hot path. A few lines copied beats importing
// DPAPI into the logon path. Keep the two in sync by hand; see
// SECURITY-FIXES.md, "Duplicated logic".
//
// Registered as:
//   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
//     Auth0 (REG_SZ) = RistrettoFilter
//
// ---------------------------------------------------------------------
// Hardening notes for anything that runs inside lsass (see also
// SECURITY-FIXES.md):
//
//  * No CRT on the decision path. swprintf_s() calls the invalid-parameter
//    handler on overflow, and the default handler terminates the process.
//    In lsass that is a bugcheck and a reboot loop. Everything here uses
//    bounded append helpers that truncate instead.
//  * SEH (__try/__except), not C++ try/catch. With /EHsc a catch(...) does
//    NOT catch access violations, so the original catch block could never
//    have fired on the failure that actually matters.
//  * The whole decision runs behind one __except that fails closed.
//  * Time comes from GetSystemTimeAsFileTime, not _time64: same value
//    (UTC unix seconds), no CRT, no locale, no heap.
// ---------------------------------------------------------------------

#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <ntsecapi.h>
#include <subauth.h>

#pragma comment(lib, "advapi32.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS             ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006EL)
#endif

// Writing to the event log from lsass is an RPC to the eventlog service;
// the conservative default on the logon path is off. The veto is always
// observable as a failed 4625 in the Security log either way.
#define RISTRETTO_FILTER_EVENTLOG 0

// Log every *allowed* logon too. Off by default: it puts account names in
// front of anything holding a debugger on the box, on every SMB connection.
#define RISTRETTO_FILTER_VERBOSE  0

namespace
{
    const wchar_t kDoppioRids[] = L"SOFTWARE\\TheAdminCafe\\2FA\\Rids";
    const wchar_t kGatePath[]   = L"SOFTWARE\\TheAdminCafe\\Ristretto\\Gate";
    const wchar_t kConfigPath[] = L"SOFTWARE\\TheAdminCafe\\Ristretto";

    // Window bounds. The registry key is SYSTEM/Administrators only, so this
    // is not a privilege boundary - it is a guard against a typo turning the
    // gate into a permanently open door. 0xFFFFFFFF seconds is 136 years.
    const DWORD kWindowDefault = 300;     // 5 min
    const DWORD kWindowMin     = 30;
    const DWORD kWindowMax     = 3600;    // 1 h

    const DWORD kConfigRefreshMs = 5000;

    // ---- bounded, CRT-free string building ---------------------------
    class Buf
    {
    public:
        Buf(WCHAR* p, SIZE_T cap) : p_(p), cap_(cap), n_(0)
        {
            if (cap_) p_[0] = L'\0';
        }

        void Str(const WCHAR* s)
        {
            if (!s) return;
            while (*s && n_ + 1 < cap_) p_[n_++] = *s++;
            if (cap_) p_[n_] = L'\0';
        }

        void U64(ULONGLONG v)
        {
            WCHAR t[21];
            int i = 0;
            do { t[i++] = (WCHAR)(L'0' + (ULONG)(v % 10)); v /= 10; } while (v && i < 20);
            while (i > 0 && n_ + 1 < cap_) p_[n_++] = t[--i];
            if (cap_) p_[n_] = L'\0';
        }

        SIZE_T Len() const { return n_; }

    private:
        WCHAR* p_;
        SIZE_T cap_;
        SIZE_T n_;
    };

    // RID as a decimal string, same convention as Doppio's 2FA\Rids values.
    //
    // Written out longhand rather than through Buf on purpose. Buf terminates
    // correctly, but /analyze cannot see that across the call and reports
    // C6054 ("might not be zero-terminated") at every use of the result. With
    // /WX that ends the build, and silencing a not-terminated warning in code
    // that runs inside lsass is the wrong habit to get into - so the
    // termination is made obvious here instead.
    //
    // A ULONG is at most 10 digits (4294967295), so out[12] always fits the
    // digits plus the terminator.
    void RidToValueName(ULONG rid, WCHAR (&out)[12])
    {
        WCHAR digits[10];
        int n = 0;
        do
        {
            digits[n++] = (WCHAR)(L'0' + (ULONG)(rid % 10));
            rid /= 10;
        } while (rid != 0 && n < 10);

        int i = 0;
        while (n > 0) out[i++] = digits[--n];
        out[i] = L'\0';                       // i <= 10, so this is in bounds
    }

    // ---- time --------------------------------------------------------
    // Identical to _time64(nullptr): UTC seconds since the unix epoch.
    ULONGLONG NowUnix()
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);          // UTC, no CRT
        ULARGE_INTEGER u;
        u.LowPart  = ft.dwLowDateTime;
        u.HighPart = ft.dwHighDateTime;
        // FILETIME counts 100 ns ticks from 1601-01-01.
        const ULONGLONG kTicksToEpoch = 116444736000000000ULL;
        if (u.QuadPart < kTicksToEpoch) return 0;
        return (u.QuadPart - kTicksToEpoch) / 10000000ULL;
    }

    // ---- config cache ------------------------------------------------
    // Several logon threads run this concurrently. Aligned 32/64-bit loads
    // are atomic on x64, and the refresh slot is claimed with an interlocked
    // compare-exchange so only one thread does the registry read.
    volatile LONG64 g_nextCfgTick = 0;
    volatile LONG   g_windowSec   = (LONG)kWindowDefault;
    volatile LONG   g_enforce     = 1;      // fail closed until told otherwise

    void ReadConfigThrottled()
    {
        const LONG64 now  = (LONG64)GetTickCount64();
        const LONG64 next = InterlockedCompareExchange64(&g_nextCfgTick, 0, 0);
        if (now < next) return;

        // Loser of the race keeps using the cached values - never blocks.
        if (InterlockedCompareExchange64(&g_nextCfgTick, now + kConfigRefreshMs, next) != next)
            return;

        DWORD v = 0, cb = sizeof(v);
        if (RegGetValueW(HKEY_LOCAL_MACHINE, kConfigPath, L"WindowSec",
                         RRF_RT_REG_DWORD, nullptr, &v, &cb) == ERROR_SUCCESS)
        {
            if (v < kWindowMin) v = kWindowMin;
            if (v > kWindowMax) v = kWindowMax;
            InterlockedExchange(&g_windowSec, (LONG)v);
        }

        cb = sizeof(v);
        if (RegGetValueW(HKEY_LOCAL_MACHINE, kConfigPath, L"Mode",
                         RRF_RT_REG_DWORD, nullptr, &v, &cb) == ERROR_SUCCESS)
            InterlockedExchange(&g_enforce, v ? 1 : 0);
        // No value / unreadable -> keep the previous (enforcing) state.
    }

    // ---- enrollment ----------------------------------------------------
    // Behavioral copy of tac::IsEnrolledByRid (store.cpp). Presence only,
    // no secret material.
    //
    // The original collapsed every failure into "not enrolled", which is
    // fail-OPEN: one unexpected registry error and an enrolled account walks
    // straight past the gate. Three outcomes now, so the caller can tell
    // "Doppio is not installed" (nothing to enforce, allow) apart from
    // "this read went wrong" (refuse this one account).
    enum class Enroll { No, Yes, Unknown };

    Enroll EnrollmentOf(ULONG rid)
    {
        if (!rid) return Enroll::No;

        HKEY k = nullptr;
        LSTATUS st = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kDoppioRids, 0, KEY_QUERY_VALUE, &k);
        if (st == ERROR_FILE_NOT_FOUND)
            return Enroll::No;          // no Doppio index at all -> nothing of ours
        if (st != ERROR_SUCCESS)
            return Enroll::Unknown;

        WCHAR value[12] = {};
        RidToValueName(rid, value);

        st = RegQueryValueExW(k, value, nullptr, nullptr, nullptr, nullptr);
        RegCloseKey(k);

        if (st == ERROR_SUCCESS)        return Enroll::Yes;
        if (st == ERROR_FILE_NOT_FOUND) return Enroll::No;
        return Enroll::Unknown;
    }

    // ---- gate ----------------------------------------------------------
    bool GateFresh(ULONG rid, ULONG& ageSec)
    {
        ageSec = 0;

        WCHAR value[12] = {};
        RidToValueName(rid, value);

        ULONGLONG ts = 0;
        DWORD cb = sizeof(ts);
        if (RegGetValueW(HKEY_LOCAL_MACHINE, kGatePath, value,
                         RRF_RT_REG_QWORD, nullptr, &ts, &cb) != ERROR_SUCCESS)
            return false;               // missing or unreadable -> closed

        const ULONGLONG now = NowUnix();
        if (now < ts) return false;     // clock moved back -> locked

        const ULONGLONG age = now - ts;
        ageSec = (ULONG)(age > 0xFFFFFFFFull ? 0xFFFFFFFFull : age);

        const ULONG window = (ULONG)InterlockedCompareExchange(&g_windowSec, 0, 0);
        return age <= (ULONGLONG)window;
    }

    // SAM name, for the log only. The decision runs on the RID alone.
    void SamName(const USER_ALL_INFORMATION* ua, WCHAR (&out)[129])
    {
        out[0] = L'?';
        out[1] = L'\0';
        if (!ua) return;

        const UNICODE_STRING& us = ua->UserName;
        if (!us.Buffer || us.Length == 0 || (us.Length % sizeof(WCHAR)) != 0)
            return;

        SIZE_T cch = us.Length / sizeof(WCHAR);
        if (cch > 128) cch = 128;
        for (SIZE_T i = 0; i < cch; ++i)
        {
            WCHAR c = us.Buffer[i];
            if (c == L'\0') { cch = i; break; }
            // Keep control characters out of the log line.
            out[i] = (c < 0x20) ? L'.' : c;
        }
        out[cch] = L'\0';
    }

    void Debug(const WCHAR* text)
    {
        WCHAR line[384];
        Buf b(line, ARRAYSIZE(line));
        b.Str(L"[Ristretto] ");
        b.Str(text);
        b.Str(L"\n");
        OutputDebugStringW(line);
    }

    void Report(WORD type, DWORD id, const WCHAR* text)
    {
        Debug(text);
#if RISTRETTO_FILTER_EVENTLOG
        HANDLE h = RegisterEventSourceW(nullptr, L"TheAdminCafe Ristretto");
        if (h)
        {
            LPCWSTR s[1] = { text };
            ReportEventW(h, type, 0, id, nullptr, 1, 0, s, nullptr);
            DeregisterEventSource(h);
        }
#else
        (void)type; (void)id;
#endif
    }

    void ReportVeto(ULONG rid, const WCHAR* name, ULONG ageSec, const WCHAR* why)
    {
        WCHAR text[320];
        Buf b(text, ARRAYSIZE(text));
        b.Str(L"Refused a network logon for enrolled account '");
        b.Str(name);
        b.Str(L"' (RID ");
        b.U64(rid);
        b.Str(L"): ");
        b.Str(why);
        b.Str(L" (last unlock ");
        b.U64(ageSec);
        b.Str(L" s ago or none).");
        Report(EVENTLOG_WARNING_TYPE, 301, text);
    }

    // Which exceptions the filter swallows.
    //
    // A constant EXCEPTION_EXECUTE_HANDLER would catch everything, and
    // /analyze is right to flag that (C6320): some exceptions must not be
    // handled. A stack overflow is the clear case - the guard page is gone by
    // the time the filter runs, so continuing on that thread is worse than
    // letting it go. Everything else here means a bad pointer from the
    // caller, and on that one the bugcheck is the worse outcome, so it is
    // caught and the logon refused.
    LONG DecisionFilter(DWORD code)
    {
        switch (code)
        {
        case EXCEPTION_STACK_OVERFLOW:
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            return EXCEPTION_CONTINUE_SEARCH;   // not ours to survive
        default:
            return EXCEPTION_EXECUTE_HANDLER;
        }
    }

    // The actual decision. Split out so the __try frame in the exported
    // function holds nothing but PODs - __try cannot coexist with objects
    // that need unwinding in the same frame.
    NTSTATUS Decide(PUSER_ALL_INFORMATION UserAll)
    {
        if (!UserAll)
            return STATUS_SUCCESS;          // nothing to judge

        ReadConfigThrottled();

        if (!InterlockedCompareExchange(&g_enforce, 0, 0))
            return STATUS_SUCCESS;          // kill switch

        const ULONG rid = UserAll->UserId;

        WCHAR name[129];
        SamName(UserAll, name);

        switch (EnrollmentOf(rid))
        {
        case Enroll::No:
            return STATUS_SUCCESS;          // not enrolled: not our business

        case Enroll::Unknown:
            // The index is there but this read failed. Do not guess "not
            // enrolled" - that is the one wrong answer that opens the gate.
            ReportVeto(rid, name, 0, L"the enrollment index could not be read");
            return STATUS_ACCOUNT_RESTRICTION;

        case Enroll::Yes:
        default:
            break;
        }

        ULONG age = 0;
        if (GateFresh(rid, age))
        {
#if RISTRETTO_FILTER_VERBOSE
            WCHAR ok[256];
            Buf b(ok, ARRAYSIZE(ok));
            b.Str(L"Gate fresh for '");
            b.Str(name);
            b.Str(L"' (RID ");
            b.U64(rid);
            b.Str(L", ");
            b.U64(age);
            b.Str(L" s old). No objection.");
            Debug(ok);
#endif
            return STATUS_SUCCESS;
        }

        ReportVeto(rid, name, age, L"no fresh gate");
        return STATUS_ACCOUNT_RESTRICTION;
    }
}

NTSTATUS NTAPI Msv1_0SubAuthenticationFilter(
    NETLOGON_LOGON_INFO_CLASS LogonLevel,
    PVOID /*LogonInformation*/,            // challenge/response - never read
    ULONG /*Flags*/,
    PUSER_ALL_INFORMATION UserAll,         // hashes live here too - never read
    PULONG WhichFields,
    PULONG /*UserFlags*/,
    PBOOLEAN Authoritative,
    PLARGE_INTEGER /*LogoffTime*/,         // account logon hours - not ours
    PLARGE_INTEGER /*KickoffTime*/)
{
    if (WhichFields)
        *WhichFields = 0;

    const bool isNetwork = (LogonLevel == NetlogonNetworkInformation ||
                            LogonLevel == NetlogonNetworkTransitiveInformation);

    // Anything that is not a network logon is out of scope, including the
    // interactive path Doppio's credential provider already owns. Leave
    // *Authoritative as MSV1_0 passed it in there: we have no opinion.
    // (FALSE would let the request be retried on another domain controller;
    // a refusal below sets TRUE so it stays final.)
    if (!isNetwork)
        return STATUS_SUCCESS;

    NTSTATUS result;

    // An access violation here would take lsass down with it, which is a
    // bugcheck and a reboot loop on the next boot. Catching it and refusing
    // is the lesser evil on the one path this filter exists for. Nothing
    // below allocates, so there is no state to unwind.
    __try
    {
        result = Decide(UserAll);
    }
    __except (DecisionFilter(GetExceptionCode()))
    {
        Report(EVENTLOG_ERROR_TYPE, 303,
               L"Unhandled exception while deciding a network logon - refusing (fail closed).");
        result = STATUS_ACCOUNT_RESTRICTION;
    }

    if (result != STATUS_SUCCESS && Authoritative)
        *Authoritative = TRUE;

    return result;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(h);
    return TRUE;
}
