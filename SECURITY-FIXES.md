# Security review and fixes

Review of the Ristretto sources (filter, gate tool, installer). Grouped by
how much they matter. Everything listed as **fixed** is in the files shipped
alongside this document.

---

## 0. The thing that is not a bug

The gate pattern converts a *per-connection* check into a *time-window*
check. While the window is open, **every** network logon for that account
passes — not only the one you opened it for. Anyone holding the password, or
the NTLMv2 material for a relay, walks through.

This is inherent to the design and the README is honest about it. It is worth
restating because it sets the ceiling on what the rest of the hardening can
buy you: the gate authenticates a *moment*, not a *connection*.

Mitigation applied: the default window dropped from 900 s to **300 s**, and
`/status` now prints the remaining time so an open gate is visible.

Not applied, deliberately: binding the gate to the client workstation name.
`NETLOGON_NETWORK_INFO.Identity.Workstation` is supplied by the client and
trivially forged, so gating on it would read like a security control while
being none.

---

## 1. Filter: `swprintf_s` could terminate lsass — **fixed**

`swprintf_s` invokes the invalid-parameter handler on overflow, and the
default handler ends the process. The process here is **lsass**, so that is a
bugcheck, and a bugcheck reached from the logon path can mean a reboot loop.

The old buffers were close: the veto message could reach ~234 of 256
characters with a 128-character account name, leaving very little headroom
for any later edit to the format string.

All formatting on the lsass path now goes through a small bounded appender
that truncates and never calls the CRT.

## 2. Filter: `catch (...)` never caught the failure that matters — **fixed**

With `/EHsc`, a C++ `catch (...)` does **not** catch SEH exceptions. An
access violation — the realistic failure mode for a bad `UNICODE_STRING`
from the caller — walked straight past that handler and into lsass.

Replaced with `__try` / `__except (EXCEPTION_EXECUTE_HANDLER)`, which does
catch it, and still fails closed. The decision body moved into `Decide()` so
the `__try` frame holds only PODs (`__try` cannot coexist with objects that
need unwinding in the same frame).

## 3. Filter: failed enrollment read was fail-**open** — **fixed**

`IsEnrolledByRid` collapsed every registry failure into "not enrolled", and
"not enrolled" returns `STATUS_SUCCESS`. One unexpected error and an enrolled
account bypasses the gate entirely.

Now three-valued:

| Condition | Result |
|---|---|
| `Rids` key absent entirely | allow — Doppio is not installed, nothing of ours to enforce |
| value absent | allow — genuinely not enrolled |
| any other error | **refuse that account** |

Keeping "key absent" permissive is intentional: failing closed there would
deny *every* network logon on the machine the moment Doppio is uninstalled.
The per-account failure path is the one that fails closed.

## 4. Filter: `WindowSec` had no upper bound — **fixed**

Any non-zero DWORD was accepted. `0xFFFFFFFF` seconds is ~136 years — a
permanently open gate, with nothing in the UI saying so.

Clamped to **30–3600 s** on *both* sides: in the filter when reading, and in
`ristretto.exe /window` when writing. Clamping on read is what matters — it
holds even if the value is set by hand in regedit.

## 5. Filter: unsynchronised config globals — **fixed**

`g_nextCfg`, `g_windowSec` and `g_enforce` were plain globals written from
concurrent logon threads. On x64 the aligned loads are atomic in practice, so
this was correctness hygiene rather than an exploitable race, but the refresh
slot is now claimed with an interlocked compare-exchange (one thread reads
the registry, the others keep using cached values and never block).

## 6. Filter: CRT on the logon path — **fixed**

`swprintf_s` pulls locale machinery, and locale machinery touches the heap —
against the file's own stated rules. `_time64` does not: it calls
`GetSystemTimeAsFileTime` and converts. It still is CRT code on the logon
path, which the file rules out. Time now comes from `GetSystemTimeAsFileTime`
directly, converted to unix seconds, which is the identical value
`_time64(nullptr)` returns. (An earlier version of this item said `_time64`
pulls locale machinery as well. It doesn't.) `ristretto.exe` uses the same conversion so
the two sides cannot disagree about what "now" means.

## 7. Filter: success logging leaked account names — **fixed**

The allow path called `OutputDebugStringW` with the account name on *every*
SMB connection, visible to anything holding a debugger on the box. Now behind
`RISTRETTO_FILTER_VERBOSE`, off by default. Vetoes still log.

Also: control characters in the SAM name are replaced before it reaches a log
line.

## 8. Installer: `PrevAuth0` invented a filter — **fixed**

If no `Auth0` was registered, the installer stored `PrevAuth0 = 'TacSubAuth'`.
Uninstalling then *set* `Auth0 = TacSubAuth` — pointing lsass at a DLL that
may not exist on that machine, on a clean system that had no sub-auth filter
at all.

Now stores a `__none__` sentinel and the uninstaller removes the value
instead. The marker is also cleared on uninstall, so a reinstall records the
real previous state rather than reusing ours.

This fix had a hole of its own, found later: see item 16. A second run of the
installer without an uninstall in between wiped the marker and recorded
`RistrettoFilter`.

## 9. Installer: config key inherited its ACL — **fixed**

`New-Item` left `HKLM\SOFTWARE\TheAdminCafe\Ristretto` with inherited
permissions. The key holds `Mode`, the enforcement kill switch. Default
`HKLM\SOFTWARE` permissions do not grant non-admin write, so this was not
directly exploitable — but a kill switch should not depend on a default
staying what you remember it being.

The hardened SDDL (`D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)`, inheritance
blocked) is now applied to the config key *and* the gate key at install time,
before any value is written, rather than lazily on the first `/window` call.

## 10. Installer: paths relative to the working directory — **fixed**

`Copy-Item .\RistrettoFilter.dll` resolved against whatever the current
directory happened to be. Now `$PSScriptRoot`, with an existence check before
anything in the registry is touched. Ordering is also explicit: DLL on disk
first, `Auth0` set last.

## 11. Uninstaller: incomplete cleanup — **fixed**

Left the event source and open gate timestamps behind. A reinstall could find
a stale gate still inside its window. Both are removed now, and `Auth0` is
restored *first* so a later failure leaves the machine on its original filter
rather than half-uninstalled.

## 12. Build flags — **fixed**

Added `/Qspectre` (relevant for code sharing an address space with secrets),
`/DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA`, and `/WX` on the filter so a new
warning in lsass-resident code fails the build rather than shipping.

`/WX` plus `/analyze` then failed on the Windows SDK itself: `bcrypt.h`
declares `PNTSTATUS` without SAL annotations and `ntsecapi.h` declares it
again with them, which raises C28301 from inside Microsoft's header. The fix
is to keep system headers out of analysis (`/analyze:external-`,
`/external:anglebrackets /external:W0`, plus `/wd28301` as a backstop) rather
than to drop `/WX` — a warning in *this* code should still stop the build.

## 13. TOTP code on the command line — **noted, not removed**

`ristretto <user> <code>` leaves the code in the process command line, which
other processes with enough access to it can read, in shell history, and in
4688 audit records when "Include command line in process creation events" is
on (it is off by default). The code
is single-use and burned immediately, so the window is small. The argument
stays for scripted use; the tool now prints a note recommending the prompt.

## 14. Duplicated logic — **one copy removed, one documented**

`EnrollmentOf` duplicated `tac::IsEnrolledByRid`, and `OpenProtected`
duplicates `store.cpp`'s static `OpenProtectedKey`. The justification for the
first one was that linking `store.cpp` would drag DPAPI into lsass. The risk
was silent drift if Doppio changed its enrollment layout or its SDDL; the
submodule pin catches build breaks, not semantic ones.

Doppio's second review moved the index reads into their own file,
`store_index.cpp`, with no DPAPI, no account lookups and no heap. The filter
now links that file and calls `tac::EnrollmentByRid`, which has exactly the
three outcomes of item 3. `EnrollmentOf` is gone, and with it the copy that
mattered most: the one that decides inside lsass.

`OpenProtected` stays a copy, now with the Doppio commit it was taken from
(2776655) next to it. Doppio's `OpenProtectedKey` no longer re-applies the
ACL to an existing key, because it runs on the logon path; `ristretto.exe` is
a console tool and keeps the repair. If you touch either side, check the
other.

## 15. Filter: contract details from the documentation — **fixed**

Doppio's second review compared its filter with the documentation of
`Msv1_0SubAuthenticationFilter`, and the same three points applied here:

- **Veto code.** The documentation lists the values the function "must
  return". `STATUS_ACCOUNT_RESTRICTION` is not one of them;
  `STATUS_INVALID_WORKSTATION` is, and it says what the gate means. A refused
  logon shows a different error text now. In the Security log, MSV1_0
  reports `STATUS_INVALID_WORKSTATION` as the sub-status of an account
  restriction, so the 4625 most likely shows Sub Status `0xC0000070` under
  Status `0xC000006E`. An earlier version of this item said Status
  `0xC0000070`; check both fields in the VM.
- **Out-parameters.** `WhichFields`, `UserFlags` and `Authoritative` are
  `[out]`, and `Authoritative` "should return valid information regardless of
  the return value". The filter set it only on a refusal and never touched
  `UserFlags`. All three are now written on every path, before the first
  return. `LogoffTime` and `KickoffTime` stay untouched: they carry the
  account's logon hours.
- **Pass-through logons.** With `MSV1_0_PASSTHRU` the user "is not connecting
  to this machine". The enrollment index only knows local RIDs, and a RID
  from another machine can collide with a local one. The filter now has no
  objection to pass-through logons.

`tests/` runs the real filter against fakes on Linux and covers all three,
plus the gate, the window bounds, the kill switch and the fail-closed paths.

## 16. Installer, uninstaller and gate tool, third review — **fixed**

A review of Part 3 against the code and the documentation found these:

- **A second install run lost the restore record (high).** The installer
  called `New-Item -Force` on the config key and the gate key. In
  PowerShell's registry provider, `-Force` on a key that exists deletes the
  key with all its values and subkeys and creates it again. A second run
  therefore lost `PrevAuth0`, `Mode`, `WindowSec` and every open gate, then
  recorded the current `Auth0`, `RistrettoFilter`, as the filter to restore.
  The uninstaller then "restored" Ristretto, and Doppio's `TacSubAuth` never
  came back. This happened before the DLL copy, so even a run that failed
  there left the wrong record. The keys are now only created when missing.
  Both scripts refuse to go on while `PrevAuth0` is `RistrettoFilter`, and the
  installer refuses when `Auth0` is already Ristretto but the record is gone.
- **LSA protection was checked through one registry value (medium).** The
  installer now also checks `RunAsPPLBoot`, WinInit event 12 since the last
  boot, and refuses on a domain controller, the same checks Doppio's
  `install-subauth.ps1` has. Before, a protected lsass meant a clean-looking
  install and a filter that never loaded.
- **Closing a gate does not end sessions (medium, documentation).** The filter
  only runs when a logon is made. A session opened inside the window stays up
  after `/close` or after the window runs out. The tool and the README now say
  so.
- **`/status` ignored the RID index (low).** It said "gate closed" for an
  account the filter does not gate at all. It now asks `tac::EnrollmentByRid`
  first.
- **`WindowSec = 0` (low).** The tool read 0 as the 300 s default; the filter
  clamps it to 30. The tool now clamps the same way.
- **`/closeall` could stop early (low).** A fixed list of 256 names of up to
  31 characters ended the loop on a long name or a full list, and the event
  still said "All gates closed". It now deletes index 0 until the key is
  empty, with room for the longest value name, and reports any error.
- **The uninstaller overwrote `Auth0` unchecked (low).** It now only restores
  the slot while it still says `RistrettoFilter`, and warns otherwise.

---

## Before you deploy this anywhere real

Two things that outrank every item above:

**The filter is an unsigned DLL running inside lsass.** A fault in it is a
bugcheck. A bugcheck reached from the logon path can leave a machine
unbootable without recovery media. The `__except` added in item 2 reduces
this; it does not eliminate it. Snapshot the VM first — the installer now
asks before it proceeds.

**`RunAsPPL` off is a real downgrade.** RunAsPPL is the protection that stops
credential-dumping tools from reading lsass memory. Turning it off to load an
unsigned filter trades a strong, broadly effective mitigation for a narrower
one. On a machine that matters, that trade is probably net negative. This
stays test-VM code until the filter is properly signed and RunAsPPL can stay
on.
