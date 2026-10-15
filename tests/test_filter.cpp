// Behaviour tests for the real src/ristretto_filter.cpp, on Linux, under
// AddressSanitizer and UBSan. Registry, event log and debugger output come
// from Doppio's fakes (extern/doppio/tests/native/lsa_fakes.cpp), the typed
// registry values and the clock from filter_fakes.cpp. The enrollment read is
// Doppio's real store_index.cpp, linked exactly as in the DLL.
//
// What this cannot show: how MSV1_0 calls the filter, and real SEH.
// __try/__except are mapped to try/catch by the shim, and the fake registry
// throws to stand in for an access violation.
#include <windows.h>
#include <subauth.h>
#include "filter_fakes.h"
#include "lsa_fakes.h"
#include <cstdio>
#include <string>

static int g_failed = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL  line %d: %s\n", __LINE__, #c); ++g_failed; } \
                      else std::printf("ok    %s\n", #c); } while (0)

static const NTSTATUS kSuccess = 0x00000000L;
static const NTSTATUS kVeto    = 0xC0000070L;    // STATUS_INVALID_WORKSTATION

static const wchar_t kRids[]   = L"SOFTWARE\\TheAdminCafe\\2FA\\Rids";
static const wchar_t kGate[]   = L"SOFTWARE\\TheAdminCafe\\Ristretto\\Gate";
static const wchar_t kConfig[] = L"SOFTWARE\\TheAdminCafe\\Ristretto";

struct Result
{
    NTSTATUS status;
    ULONG    which;
    ULONG    userFlags;
    BOOLEAN  authoritative;
    LONGLONG logoff;
    LONGLONG kickoff;
};

static Result Call(NETLOGON_LOGON_INFO_CLASS level, ULONG flags, ULONG rid,
                   std::wstring name = L"alice", bool noUser = false)
{
    USER_ALL_INFORMATION ua = {};
    ua.UserId = rid;
    ua.UserName.Buffer        = name.empty() ? nullptr : &name[0];
    ua.UserName.Length        = static_cast<USHORT>(name.size() * sizeof(WCHAR));
    ua.UserName.MaximumLength = ua.UserName.Length;

    ULONG which = 0xFFFF, userFlags = 0xFFFF;
    BOOLEAN authoritative = 2;
    LARGE_INTEGER logoff, kickoff;
    logoff.QuadPart  = 111;
    kickoff.QuadPart = 222;

    NTSTATUS s = Msv1_0SubAuthenticationFilter(level, nullptr, flags, noUser ? nullptr : &ua,
                                               &which, &userFlags, &authoritative,
                                               &logoff, &kickoff);
    return { s, which, userFlags, authoritative, logoff.QuadPart, kickoff.QuadPart };
}

// [out] parameters valid on every path, logon hours left alone.
static bool Sane(const Result& r)
{
    return r.which == 0 && r.userFlags == 0 && r.authoritative == TRUE &&
           r.logoff == 111 && r.kickoff == 222;
}

static void Gate(ULONG rid, ULONGLONG ageSec)
{
    rt::values[{ kGate, std::to_wstring(rid) }] = { RRF_RT_REG_QWORD, rt::nowUnix - ageSec };
}

static void Config(const wchar_t* name, DWORD value)
{
    rt::values[{ kConfig, name }] = { RRF_RT_REG_DWORD, value };
    rt::tickMs += 5001;                     // past the 5 s config cache
}

int main()
{
    fake::Reset();
    rt::Reset();
    fake::keys[kRids] = { L"1001", L"4294967295" };

    std::printf("-- scope: what the filter has no opinion on\n");
    Result r = Call(NetlogonInteractiveInformation, 0, 1001);
    CHECK(r.status == kSuccess && Sane(r));                 // not network
    r = Call(NetlogonNetworkInformation, MSV1_0_PASSTHRU, 1001);
    CHECK(r.status == kSuccess && Sane(r));                 // not this machine
    r = Call(NetlogonNetworkInformation, 0, 1002, L"bob");
    CHECK(r.status == kSuccess && Sane(r));                 // not enrolled
    r = Call(NetlogonInteractiveInformation, 0, 1001, L"", true);
    CHECK(r.status == kSuccess && Sane(r));                 // no SAM record, not network

    std::printf("-- the gate\n");
    r = Call(NetlogonNetworkInformation, 0, 1001);
    CHECK(r.status == kVeto && Sane(r));                    // enrolled, no gate
    CHECK(fake::DebugContains(L"no fresh gate"));
    Gate(1001, 10);
    r = Call(NetlogonNetworkInformation, 0, 1001);
    CHECK(r.status == kSuccess && Sane(r));                 // fresh (default 300 s)
    r = Call(NetlogonNetworkTransitiveInformation, 0, 1001);
    CHECK(r.status == kSuccess);
    Gate(1001, 301);
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kVeto);   // stale
    Gate(1001, 300);
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kSuccess); // edge: still fresh
    rt::values[{ kGate, L"1001" }] = { RRF_RT_REG_QWORD, rt::nowUnix + 60 };
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kVeto);   // clock moved back
    rt::values[{ kGate, L"1001" }] = { RRF_RT_REG_DWORD, rt::nowUnix };
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kVeto);   // wrong type
    Gate(4294967295u, 5);
    CHECK(Call(NetlogonNetworkInformation, 0, 4294967295u).status == kSuccess); // 10-digit RID

    std::printf("-- config: window bounds and the kill switch\n");
    Config(L"WindowSec", 10);                               // below 30 -> 30
    Gate(1001, 25);
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kSuccess);
    Gate(1001, 31);
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kVeto);
    Config(L"WindowSec", 999999);                           // above 3600 -> 3600
    Gate(1001, 3600);
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kSuccess);
    Gate(1001, 3601);
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kVeto);
    Config(L"Mode", 0);                                     // kill switch
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kSuccess);
    CHECK(Call(NetlogonNetworkInformation, 0, 1001, L"", true).status == kSuccess);
    Config(L"Mode", 1);
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kVeto);
    rt::values.erase({ kConfig, L"Mode" });
    rt::tickMs += 5001;
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kVeto);   // missing Mode keeps enforcing

    std::printf("-- fail closed\n");
    r = Call(NetlogonNetworkInformation, 0, 1001, L"", true);
    CHECK(r.status == kVeto && Sane(r));                    // no SAM record
    CHECK(fake::DebugContains(L"no SAM record"));
    fake::keys.erase(kRids);
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kSuccess); // Doppio not installed
    fake::keys[kRids] = { L"1001" };
    fake::openStatus = ERROR_ACCESS_DENIED;
    r = Call(NetlogonNetworkInformation, 0, 1002, L"bob");
    CHECK(r.status == kVeto && Sane(r));                    // unreadable index
    CHECK(fake::DebugContains(L"could not be read"));
    fake::openStatus = ERROR_SUCCESS;
    rt::getStatus = ERROR_ACCESS_DENIED;
    Gate(1001, 1);
    CHECK(Call(NetlogonNetworkInformation, 0, 1001).status == kVeto);   // unreadable gate
    rt::getStatus = ERROR_SUCCESS;
    fake::throwOnOpen = true;
    r = Call(NetlogonNetworkInformation, 0, 1001);
    CHECK(r.status == kVeto && Sane(r));                    // fault: refuse
    CHECK(fake::DebugContains(L"Unhandled exception"));
    CHECK(Call(NetlogonInteractiveInformation, 0, 1001).status == kSuccess);
    fake::throwOnOpen = false;

    std::printf("-- robustness\n");
    rt::values.erase({ kGate, L"1001" });                   // gate closed again
    USER_ALL_INFORMATION ua = {};
    ua.UserId = 1001;
    CHECK(Msv1_0SubAuthenticationFilter(NetlogonNetworkInformation, nullptr, 0, &ua, nullptr,
                                        nullptr, nullptr, nullptr, nullptr) == kVeto);
    fake::debug.clear();
    Call(NetlogonNetworkInformation, 0, 1002, std::wstring(L"ev\0il", 5));
    fake::keys[kRids] = { L"1001", L"1002" };
    Call(NetlogonNetworkInformation, 0, 1002, std::wstring(L"ev\0il", 5));
    CHECK(fake::DebugContains(L"'ev'") && !fake::DebugContains(L"il'"));  // stops at NUL
    Call(NetlogonNetworkInformation, 0, 1002, std::wstring(400, L'x'));
    CHECK(!fake::debug.empty() && fake::debug.back().size() < 384);       // cut, not overflowed
    CHECK(fake::opened == fake::closed);

    std::printf("\n%s (%d failed)\n", g_failed ? "SOME CHECKS FAILED" : "ALL CHECKS PASS", g_failed);
    return g_failed ? 1 : 0;
}
