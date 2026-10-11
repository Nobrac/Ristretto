// ristretto.exe - opens the network gate for an enrolled local account.
//
// Verifies the TOTP through Doppio's own verify.cpp (linked UNMODIFIED), so
// lockout, replay protection and the shared state file behave exactly like at
// the logon tile:
//   - one failure counter for tile and gate (5 free, then doubling locks
//     5 -> 10 -> 20 -> 40 -> 60 min, capped)
//   - a code burned at the tile is Replayed here, and vice versa
//   - while locked, the code is not even checked
//
// Deliberately checks the code WITHOUT a password proof (verify.h says
// "password first" for the logon path). Acceptable here because: the gate
// grants nothing by itself (NTLM still checks the password at connection
// time), the tool is admin-only by three independent ACLs (state.lock file,
// State key, DPAPI secret), and the obvious fix is circular - LogonUserW with
// LOGON32_LOGON_NETWORK is vetoed by our own filter while the gate is closed.
//
// IMPORTANT: install this exe NEXT TO TacProvider.dll (same folder).
// Doppio's StateLock lives in the module's own directory - only the same
// directory means the same lock file, which is what makes the tile and the
// gate mutually exclusive.
//
// Run elevated: the secret value is ACL'd to SYSTEM + Administrators, and
// LoadSecretKey (DPAPI, machine scope) runs in this process.
//
// Doppio files used, unmodified: totp.cpp, store.cpp, verify.cpp, statelock.cpp.

#include <windows.h>
#include "verify.h"
#include "store.h"
#include <sddl.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>

#pragma comment(lib, "advapi32.lib")

namespace
{
    const wchar_t kGatePath[]   = L"SOFTWARE\\TheAdminCafe\\Ristretto\\Gate";
    const wchar_t kConfigPath[] = L"SOFTWARE\\TheAdminCafe\\Ristretto";

    // Same ACL Doppio uses for its store (store.cpp, kKeySddl). The filter
    // reads the gate as SYSTEM; a normal user cannot forge a timestamp.
    const wchar_t kKeySddl[]    = L"D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)";

    // Must match ristretto_filter.cpp. The filter clamps on read as well -
    // clamping on both sides means a value written by hand with regedit
    // still cannot produce a gate that never closes.
    const DWORD kWindowDefault = 300;
    const DWORD kWindowMin     = 30;
    const DWORD kWindowMax     = 3600;
}

// Identical value to _time64(nullptr) and to the filter's NowUnix():
// UTC seconds since the unix epoch. Both sides must agree exactly, so both
// now derive it the same way instead of trusting two different clocks.
static uint64_t NowUnix()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    const uint64_t kTicksToEpoch = 116444736000000000ULL;
    if (u.QuadPart < kTicksToEpoch) return 0;
    return (u.QuadPart - kTicksToEpoch) / 10000000ULL;
}

static bool Elevated()
{
    HANDLE t = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t))
        return false;
    TOKEN_ELEVATION e; DWORD cb = sizeof(e);
    BOOL ok = GetTokenInformation(t, TokenElevation, &e, sizeof(e), &cb);
    CloseHandle(t);
    return ok && e.TokenIsElevated;
}

static void GateLog(WORD type, DWORD id, const std::wstring& text)
{
    HANDLE h = RegisterEventSourceW(nullptr, L"TheAdminCafe Ristretto");
    if (h)
    {
        LPCWSTR s[1] = { text.c_str() };
        ReportEventW(h, type, 0, id, nullptr, 1, 0, s, nullptr);
        DeregisterEventSource(h);
    }
}

// store.cpp's OpenProtectedKey is static; this is an intentional copy, taken
// from Doppio 2776655. Creates or opens a key below HKLM with the protected
// ACL, and re-applies the ACL on existing keys. Doppio's own OpenProtectedKey
// stopped re-applying it in 37a827d, because Doppio's SaveState runs on the
// logon path; its enroll.exe repairs the ACL once per run instead. This tool
// is a console tool like enroll.exe, so the repair stays here on purpose.
static LSTATUS OpenProtected(const wchar_t* path, HKEY* phKey)
{
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kKeySddl, SDDL_REVISION_1,
                                                              &psd, nullptr))
        return static_cast<LSTATUS>(GetLastError());
    SECURITY_ATTRIBUTES sa = { sizeof(sa), psd, FALSE };
    DWORD disp = 0;
    LSTATUS st = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, nullptr, 0,
                                 KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC,
                                 &sa, phKey, &disp);
    if (st == ERROR_SUCCESS && disp == REG_OPENED_EXISTING_KEY)
    {
        st = RegSetKeySecurity(*phKey, DACL_SECURITY_INFORMATION, psd);
        if (st != ERROR_SUCCESS) { RegCloseKey(*phKey); *phKey = nullptr; }
    }
    LocalFree(psd);
    return st;
}

static DWORD CurrentWindowSec()
{
    DWORD v = 0, cb = sizeof(v);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kConfigPath, L"WindowSec",
                     RRF_RT_REG_DWORD, nullptr, &v, &cb) != ERROR_SUCCESS || !v)
        return kWindowDefault;
    if (v < kWindowMin) v = kWindowMin;
    if (v > kWindowMax) v = kWindowMax;
    return v;
}

static bool WriteTs(DWORD rid, uint64_t ts)   // ts = 0 deletes the value
{
    HKEY k = nullptr;
    if (OpenProtected(kGatePath, &k) != ERROR_SUCCESS)
        return false;
    WCHAR value[16];
    swprintf_s(value, L"%lu", static_cast<unsigned long>(rid));  // same convention as 2FA\Rids
    LSTATUS st = ts ? RegSetValueExW(k, value, 0, REG_QWORD,
                                     reinterpret_cast<const BYTE*>(&ts), sizeof(ts))
                    : RegDeleteValueW(k, value);
    RegCloseKey(k);
    return st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND;
}

static bool RidOf(const wchar_t* user, std::wstring& sid, DWORD& rid)
{
    // Doppio's own resolution: normalizes, qualifies as COMPUTERNAME\user,
    // requires a real local SAM account. Local-only scope comes with it.
    if (!tac::ResolveLocalUserSid(user, sid))
        return false;
    return tac::RidFromSidString(sid, rid);
}

static int Open(const wchar_t* user, const wchar_t* codeArg)
{
    std::wstring sid; DWORD rid = 0;
    if (!RidOf(user, sid, rid))
    {
        wprintf(L"'%s' is not a local user account on this machine.\n", user);
        return 1;
    }

    WCHAR codeBuf[16] = {};
    if (codeArg && *codeArg)
    {
        // The code is single-use and burned below, so the exposure window is
        // short - but a command line is readable by any process on the box
        // and lands in 4688 audit records and shell history. Prompting is
        // the better habit; the argument stays for scripted use.
        wprintf(L"Note: passing the code as an argument leaves it in the command line "
                L"and in your shell history. Prefer running without it.\n");
        wcsncpy_s(codeBuf, codeArg, _TRUNCATE);
    }
    else
    {
        wprintf(L"One-time code: ");
        if (!fgetws(codeBuf, ARRAYSIZE(codeBuf), stdin))
            return 1;
    }
    std::wstring code(codeBuf);
    SecureZeroMemory(codeBuf, sizeof(codeBuf));
    while (!code.empty() && (code.back() == L'\n' || code.back() == L'\r' || code.back() == L' '))
        code.pop_back();

    tac::OtpInfo info = {};
    tac::OtpResult r = tac::VerifyOtp(sid, code, NowUnix(), info);
    if (!code.empty())
        SecureZeroMemory(&code[0], code.size() * sizeof(WCHAR));

    switch (r)
    {
    case tac::OtpResult::Ok:
        break;
    case tac::OtpResult::NotEnrolled:
        wprintf(L"'%s' is not enrolled in Doppio. Run enroll.exe first.\n", user);
        return 1;
    case tac::OtpResult::LockedOut:
        wprintf(L"Locked. Try again in %u minutes. "
                L"(The gate and the logon screen share one lockout.)\n", info.minutesLeft);
        return 1;
    case tac::OtpResult::Error:
        wprintf(L"Could not lock/read/write the 2FA state. Nothing opened.\n");
        return 1;
    case tac::OtpResult::Replayed:
        wprintf(L"That code was already used. Wait for the next one - and note that "
                L"retrying a used code counts as a failure (%u in a row%s).\n",
                info.failures, info.minutesLeft ? L", account now locked" : L"");
        return 1;
    default:   // Wrong
        if (info.minutesLeft)
            wprintf(L"Invalid one-time code. %u in a row - account locked for %u minutes.\n",
                    info.failures, info.minutesLeft);
        else
            wprintf(L"Invalid one-time code. (%u in a row)\n", info.failures);
        return 1;
    }

    // The code is burned now (lastStep was saved). If the timestamp write
    // fails, the user re-runs with the next code - annoying, never unsafe.
    if (!WriteTs(rid, NowUnix()))
    {
        wprintf(L"Code accepted, but the gate timestamp could not be written (elevated?).\n");
        return 1;
    }

    const DWORD window = CurrentWindowSec();
    GateLog(EVENTLOG_INFORMATION_TYPE, 300,
            std::wstring(L"Gate opened for '") + user + L"' (RID " + std::to_wstring(rid) +
            L") for " + std::to_wstring(window) + L" s.");
    wprintf(L"Gate open for '%s' for %lu s.\n"
            L"Anyone who can authenticate as this account passes while the window lasts -\n"
            L"close it with /close when you are done.\n",
            user, static_cast<unsigned long>(window));
    return 0;
}

static int Status(const wchar_t* user)
{
    std::wstring sid; DWORD rid = 0;
    if (!RidOf(user, sid, rid))
    {
        wprintf(L"'%s' is not a local user account.\n", user);
        return 1;
    }

    DWORD mode = 1, cb = sizeof(mode);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kConfigPath, L"Mode",
                     RRF_RT_REG_DWORD, nullptr, &mode, &cb) != ERROR_SUCCESS)
        mode = 1;
    if (!mode)
        wprintf(L"WARNING: Mode = 0, enforcement is off. The filter lets every network "
                L"logon through regardless of the gate.\n");

    WCHAR value[16];
    swprintf_s(value, L"%lu", static_cast<unsigned long>(rid));
    ULONGLONG ts = 0; cb = sizeof(ts);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kGatePath, value,
                     RRF_RT_REG_QWORD, nullptr, &ts, &cb) != ERROR_SUCCESS)
    {
        wprintf(L"'%s': gate closed (never opened).\n", user);
        return 0;
    }

    const uint64_t now = NowUnix();
    if (now < ts)
    {
        wprintf(L"'%s': clock skew, the filter treats this as closed.\n", user);
        return 0;
    }

    const uint64_t age    = now - ts;
    const DWORD    window = CurrentWindowSec();
    if (age <= window)
        wprintf(L"'%s': gate OPEN, %llu s remaining (opened %llu s ago, window %lu s).\n",
                user, (unsigned long long)(window - age), (unsigned long long)age,
                static_cast<unsigned long>(window));
    else
        wprintf(L"'%s': gate closed (expired; last unlock %llu s ago, window %lu s).\n",
                user, (unsigned long long)age, static_cast<unsigned long>(window));
    return 0;
}

static int Close(const wchar_t* user)
{
    std::wstring sid; DWORD rid = 0;
    if (!RidOf(user, sid, rid)) { wprintf(L"unknown account\n"); return 1; }
    bool ok = WriteTs(rid, 0);
    if (ok)
        GateLog(EVENTLOG_INFORMATION_TYPE, 302,
                std::wstring(L"Gate closed for '") + user + L"'.");
    wprintf(ok ? L"closed\n" : L"close failed\n");
    return ok ? 0 : 1;
}

// Panic button: drop every open gate at once without having to remember who
// is enrolled.
static int CloseAll()
{
    HKEY k = nullptr;
    if (OpenProtected(kGatePath, &k) != ERROR_SUCCESS)
    {
        wprintf(L"Could not open the gate key (elevated?).\n");
        return 1;
    }

    // Collect first, delete after: deleting while enumerating shifts indices.
    std::wstring names[256];
    DWORD count = 0;
    for (DWORD i = 0; count < ARRAYSIZE(names); ++i)
    {
        WCHAR name[32]; DWORD cch = ARRAYSIZE(name);
        if (RegEnumValueW(k, i, name, &cch, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        names[count++] = name;
    }
    DWORD closed = 0;
    for (DWORD i = 0; i < count; ++i)
        if (RegDeleteValueW(k, names[i].c_str()) == ERROR_SUCCESS)
            ++closed;
    RegCloseKey(k);

    GateLog(EVENTLOG_INFORMATION_TYPE, 302,
            L"All gates closed (" + std::to_wstring(closed) + L").");
    wprintf(L"closed %lu gate(s)\n", static_cast<unsigned long>(closed));
    return 0;
}

static int SetWindow(const wchar_t* arg)
{
    long raw = _wtol(arg);
    if (raw <= 0)
    {
        wprintf(L"Give the window in seconds, %lu-%lu.\n",
                static_cast<unsigned long>(kWindowMin), static_cast<unsigned long>(kWindowMax));
        return 1;
    }
    DWORD v = static_cast<DWORD>(raw);
    if (v < kWindowMin || v > kWindowMax)
    {
        DWORD clamped = v < kWindowMin ? kWindowMin : kWindowMax;
        wprintf(L"%lu s is outside the allowed range %lu-%lu; using %lu s.\n",
                static_cast<unsigned long>(v),
                static_cast<unsigned long>(kWindowMin),
                static_cast<unsigned long>(kWindowMax),
                static_cast<unsigned long>(clamped));
        v = clamped;
    }

    HKEY k = nullptr;
    if (OpenProtected(kConfigPath, &k) != ERROR_SUCCESS)
    {
        wprintf(L"Could not open the config key (elevated?).\n");
        return 1;
    }
    LSTATUS st = RegSetValueExW(k, L"WindowSec", 0, REG_DWORD,
                                reinterpret_cast<const BYTE*>(&v), sizeof(v));
    RegCloseKey(k);
    if (st != ERROR_SUCCESS) { wprintf(L"write failed\n"); return 1; }
    wprintf(L"WindowSec = %lu (active within ~5 s, no reboot)\n",
            static_cast<unsigned long>(v));
    return 0;
}

static int SetMode(const wchar_t* arg)
{
    const bool gate = !_wcsicmp(arg, L"gate");
    if (!gate && _wcsicmp(arg, L"off"))
    {
        wprintf(L"Use 'gate' or 'off'.\n");
        return 1;
    }
    DWORD v = gate ? 1u : 0u;

    HKEY k = nullptr;
    if (OpenProtected(kConfigPath, &k) != ERROR_SUCCESS)
    {
        wprintf(L"Could not open the config key (elevated?).\n");
        return 1;
    }
    LSTATUS st = RegSetValueExW(k, L"Mode", 0, REG_DWORD,
                                reinterpret_cast<const BYTE*>(&v), sizeof(v));
    RegCloseKey(k);
    if (st != ERROR_SUCCESS) { wprintf(L"write failed\n"); return 1; }

    GateLog(gate ? EVENTLOG_INFORMATION_TYPE : EVENTLOG_WARNING_TYPE, 304,
            gate ? L"Enforcement enabled (Mode = 1)."
                 : L"Enforcement DISABLED (Mode = 0) - network logons are no longer gated.");
    if (gate)
        wprintf(L"Mode = gate (active within ~5 s, no reboot)\n");
    else
        wprintf(L"Mode = off. Enforcement is DISABLED: every network logon passes, "
                L"gate or not. Re-enable with /mode gate.\n");
    return 0;
}

int wmain(int argc, wchar_t** argv)
{
    if (!Elevated())
    {
        wprintf(L"Run elevated. The 2FA store, state and lock are SYSTEM/Administrators only.\n");
        return 1;
    }

    if (argc >= 2 && argv[1][0] != L'/')
        return Open(argv[1], argc > 2 ? argv[2] : nullptr);

    if (argc == 3 && !_wcsicmp(argv[1], L"/status"))  return Status(argv[2]);
    if (argc == 3 && !_wcsicmp(argv[1], L"/close"))   return Close(argv[2]);
    if (argc == 2 && !_wcsicmp(argv[1], L"/closeall"))return CloseAll();
    if (argc == 3 && !_wcsicmp(argv[1], L"/window"))  return SetWindow(argv[2]);
    if (argc == 3 && !_wcsicmp(argv[1], L"/mode"))    return SetMode(argv[2]);

    wprintf(L"ristretto <user> [code]     open the network gate (TOTP check)\n"
            L"ristretto /status <user>    show gate state and time remaining\n"
            L"ristretto /close <user>     close the gate now\n"
            L"ristretto /closeall         close every open gate\n"
            L"ristretto /window <sec>     gate lifetime, %lu-%lu (default %lu)\n"
            L"ristretto /mode gate|off    enforcement kill switch, no reboot\n",
            static_cast<unsigned long>(kWindowMin),
            static_cast<unsigned long>(kWindowMax),
            static_cast<unsigned long>(kWindowDefault));
    return argc == 1 ? 0 : 1;
}
