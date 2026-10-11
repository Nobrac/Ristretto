# Ristretto

**TOTP-gated network logons for local Windows accounts.** Doppio watches the
logon screen; Ristretto decides who may come in over the network — SMB, RPC,
WinRM over NTLM.

Ristretto is a companion to [Doppio](https://github.com/Nobrac/Doppio), not a
patch. It requires Doppio to be installed and enrolled. It reads Doppio's RID
enrollment index read-only and verifies one-time codes through Doppio's own
`verify.cpp`, linked unmodified. No code changes to Doppio, no second secret
store, no second enrollment.

Blog series at <https://theadmincafe.ch>: Part 1 (credential provider),
Part 2 (inside LSA), Part 3 (this). The article is in `docs/` as well.

> **Test-VM code.** Unsigned, needs `RunAsPPL` off, runs inside `lsass.exe`.
> Same ground rules as Doppio: throwaway VM, snapshot before every reboot,
> BitLocker recovery key within reach, and a practised way to edit the
> registry offline from WinRE.

## Why it exists

Doppio's filter (Part 2) flatly denies network logons for enrolled accounts —
correct, but it means an enrolled account can never map a share, never use
WinRM, and RDP with NLA stops working for it. The second factor made the
account safer by making it useless.

A real second factor per SMB connection is impossible: NTLMv2 is
challenge/response, the password never crosses the wire, and there is no
round trip in the handshake where a server can ask for a code. So Ristretto
uses the **gate pattern** instead: prove your TOTP once, get a time window,
network logons pass while the window is open. Same idea as Duo's remembered
sessions, minus the cloud.

```
ristretto alice            →  TOTP checked, timestamp written
net use \\host\share       →  filter sees a fresh gate, no objection
...5 minutes later...
net use \\host\share       →  gate stale, STATUS_INVALID_WORKSTATION
```

## Read this before you decide it is what you want

Ristretto is **not** a security improvement over Doppio's filter. It is a
controlled loosening of it. Three limits decide whether it is any use to you:

1. **The window is account-wide, not connection-wide.** While a gate is open,
   anyone who can authenticate as that account gets in — not only the person
   who opened it. Password holders, pass-the-hash, a well-timed relay. The
   gate proves somebody with the phone was at this machine recently. It does
   not prove anything about the connection in front of it.

2. **The gate is opened on the machine it protects, elevated.** You need an
   interactive session on the box to unlock network access *to* the box. On a
   headless server that is a deadlock. An unattended backup job at 03:00
   arrives as a network logon with nobody awake to open a gate for it. What is
   left is the case where you already have console access and want network
   access from a second machine for a while.

3. **`RunAsPPL` has to be off.** That is what lets Windows load the unsigned
   DLL, and it is also what stops credential-dumping tools reading passwords
   out of lsass memory. On a machine that matters, that trade is probably a
   net loss.

If you just need one account to reach a share, the boring answer is usually
better: a **separate, non-enrolled account** for network access with minimal
rights and a long random password. No code in lsass, no `RunAsPPL` off. The
account at the logon screen stays fully protected by Doppio.

## How it works

| Piece | Runs in | Does |
|---|---|---|
| `RistrettoFilter.dll` | `lsass.exe`, MSV1_0 `Auth0` slot | Vetoes a network logon for an enrolled account unless its gate is fresh |
| `ristretto.exe` | an elevated console | Checks a TOTP through Doppio's `verify.cpp` and writes the gate timestamp |

The filter asks four questions per logon, in this order, and three of them
exit to "no objection" at the cost of one registry read at most:

```
network logon to this machine? → no  → no objection   (pass-through counts as no)
enforcement on?                → off → no objection
enrolled (RID)?                → no  → no objection   (unreadable index → refuse)
gate fresh?                    → no  → veto
```

The veto is `STATUS_INVALID_WORKSTATION`, the same code Doppio's filter
returns, so from MSV1_0's side nothing about the refusal changed — only the
condition in front of it. In the Security log a refusal is a failed 4625 with
status `0xC0000070`. `WhichFields`, `UserFlags` and `Authoritative` are
written on every path, as the documentation of
`Msv1_0SubAuthenticationFilter` asks; `SECURITY-FIXES.md`, item 15, has the
details.

The enrollment check is Doppio's own `tac::EnrollmentByRid` from
`store_index.cpp`, linked into the DLL. That file holds the index reads and
nothing else: no DPAPI, no account lookups, no heap.

### One lockout, not two

`ristretto.exe` links Doppio's `totp.cpp`, `store.cpp`, `store_index.cpp`,
`verify.cpp` and `statelock.cpp` **unmodified**, as a pinned submodule. That is not laziness —
it is the only way the lockout stays honest. A separate failure counter would
give an attacker two independent sets of guesses against the same secret.

Sharing `verify.cpp` means one counter, one `lastStep`, one state file: five
wrong codes lock the account whether they were typed at the tile or at the
gate, a code burned at one is `Replayed` at the other, and while the account
is locked the code is not even checked.

> **`ristretto.exe` must sit in the same folder as `TacProvider.dll`.**
> Doppio's `StateLock` builds its lock file path from the calling module's own
> directory. Somewhere else means a second lock file, which means the tile and
> the gate can write the state at the same time, which means the shared counter
> is no longer shared. The installer puts it in
> `C:\Program Files\TheAdminCafe\` for exactly this reason.

## Build

```text
git clone https://github.com/Nobrac/Ristretto
cd Ristretto
git submodule update --init --recursive
build-ristretto.bat
```

From the **x64 Native Tools Command Prompt** — a plain `cmd` has neither
`cl.exe` nor the SDK headers on the PATH.

The filter is built with `/MT /O2 /guard:cf /Qspectre /W4 /WX /sdl` and
linked `/CETCOMPAT /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA`. `/WX` is
deliberate: a new warning in code that lives inside lsass should fail the
build, not ship. `/analyze` runs as a second, advisory pass.

### Tests

```text
make -C tests
```

On Linux with g++, under AddressSanitizer and UBSan. The test compiles the
real `src/ristretto_filter.cpp` and Doppio's `store_index.cpp` against fakes
for the registry, the clock and the debugger output, and calls the exported
function the way MSV1_0 would: scope, pass-through, the gate and its edges,
the window bounds, the kill switch, the fail-closed paths and the
out-parameters. It cannot show how MSV1_0 really calls the filter, and SEH is
mapped to `try`/`catch`. CI runs it on every push.

## Install

Doppio has to be installed and enrolled first, with `enroll /reindex` run at
least once so the RID index exists. The installer refuses without it.

```powershell
.\install-ristretto.ps1
```

It checks that Doppio is there, that `RunAsPPL` is off, and that `Auth0`
belongs to `TacSubAuth` or to nobody — it will not take the slot from another
product's filter. It saves what was there, hardens the config and gate keys
before writing anything into them, copies `RistrettoFilter.dll` to System32,
puts `ristretto.exe` next to `TacProvider.dll`, and sets `Auth0` last, once the
DLL is actually on disk. It asks you to confirm first. Reboot to load it.

```text
ristretto <user> [code]     open the network gate (TOTP check)
ristretto /status <user>    show gate state and time remaining
ristretto /close <user>     close the gate now
ristretto /closeall         close every open gate
ristretto /window <sec>     gate lifetime, 30-3600 (default 300)
ristretto /mode gate|off    enforcement kill switch, no reboot
```

Pass the code as an argument only in a script — it ends up in the command
line, in 4688 audit records and in your shell history. The tool says so when
you do it.

**First thing to check in the VM:** attach a kernel debugger and watch for
`[Ristretto]` lines on a network logon. Microsoft documents `Auth0` for domain
controllers; whether MSV1_0 calls it for local accounts on a workstation is
the open question from Part 2. No lines means the filter is loaded and never
asked, and the gate is decorative.

## Uninstall

```powershell
.\uninstall-ristretto.ps1
```

Then reboot, and only **then** delete `RistrettoFilter.dll` from System32 —
lsass holds it until the machine restarts. The script restores `Auth0` first,
so a failure halfway through leaves the machine on Doppio's filter rather than
on nothing. Open gates are cleared so a later reinstall cannot find a stale
timestamp still inside its window.

## Registry

| Key | Holds |
|---|---|
| `HKLM\SOFTWARE\TheAdminCafe\Ristretto` | `Mode` (kill switch), `WindowSec`, `PrevAuth0` |
| `HKLM\SOFTWARE\TheAdminCafe\Ristretto\Gate` | one `REG_QWORD` per RID: the unix time its gate was opened |
| `HKLM\SOFTWARE\TheAdminCafe\2FA\Rids` | Doppio's enrollment index — **read-only to Ristretto** |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | `Auth0` = `RistrettoFilter` |

Both Ristretto keys get `D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)` — SYSTEM and
Administrators only, inheritance blocked — applied at install time, before any
value is written into them.

## Layout

```
src/ristretto_filter.cpp    the Auth0 filter (lsass: no heap, no CRT, SEH)
src/ristretto.cpp           the gate tool
src/RistrettoFilter.def     one export
build-ristretto.bat         both binaries
install-ristretto.ps1       registration, with the guards
uninstall-ristretto.ps1     deregistration, Auth0 restored first
SECURITY-FIXES.md           the audit findings and what each fix was for
tests/                      behaviour test of the filter (Linux, ASan/UBSan)
docs/                       the blog article
extern/                     the pinned Doppio submodule
```

`SECURITY-FIXES.md` is worth reading even if you never install this. Four of
the findings were real bugs in the first draft, three of them copied from code
that was safe where it came from.

## Licence

MIT, same as Doppio. See `LICENSE`.
