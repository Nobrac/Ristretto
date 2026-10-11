// Test-only <subauth.h>: Doppio's shim plus the extern "C" prototype that the
// Windows SDK's subauth.h declares, so the filter gets the same C linkage as
// in the real build.
#pragma once
#include_next <subauth.h>

extern "C" NTSTATUS NTAPI Msv1_0SubAuthenticationFilter(
    NETLOGON_LOGON_INFO_CLASS LogonLevel, PVOID LogonInformation, ULONG Flags,
    PUSER_ALL_INFORMATION UserAll, PULONG WhichFields, PULONG UserFlags,
    PBOOLEAN Authoritative, PLARGE_INTEGER LogoffTime, PLARGE_INTEGER KickoffTime);
