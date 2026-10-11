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

`_time64` and `swprintf_s` pull locale machinery, and locale machinery
touches the heap — against the file's own stated rules. Time now comes from
`GetSystemTimeAsFileTime` converted to unix seconds, which is the identical
value `_time64(nullptr)` returns. `ristretto.exe` uses the same conversion so
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
any process can read, and in 4688 audit records and shell history. The code
is single-use and burned immediately, so the window is small. The argument
stays for scripted use; the tool now prints a note recommending the prompt.

## 14. Duplicated logic — **documented**

`EnrollmentOf` duplicates `tac::IsEnrolledByRid`, and `OpenProtected`
duplicates `store.cpp`'s static `OpenProtectedKey`. The justification holds
(linking `store.cpp` would drag DPAPI into lsass). The risk is silent drift
if Doppio changes its enrollment layout or its SDDL — the submodule pin
catches build breaks, not semantic ones.

If you touch either side, check the other. Worth recording the Doppio commit
the copies were taken from, next to each one.

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
