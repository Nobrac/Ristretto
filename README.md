# Ristretto

TOTP-gated network logons (SMB, RPC, WinRM over NTLM) for local Windows
accounts.

Ristretto is a companion to [Doppio](https://github.com/Nobrac/Doppio) and
requires Doppio to be installed and enrolled. It reads Doppio's RID enrollment
index read-only and verifies codes through Doppio's own `verify.cpp`, linked
unmodified. Doppio needs no code changes, and there is no second secret store
or enrollment.

Blog series at <https://theadmincafe.ch>: Part 1 (credential provider), Part 2
(inside LSA), Part 3 (this project):
<https://theadmincafe.ch/p/windows-2fa-gating-network-logons/>.

> **Test-VM code.** Unsigned, needs `RunAsPPL` off, runs inside `lsass.exe`.
> Same ground rules as Doppio: throwaway VM, snapshot before every reboot,
> BitLocker recovery key within reach, and a practised way to edit the
> registry offline from WinRE.

## What it does

Doppio's filter (Part 2) denies all network logons for enrolled accounts, so
an enrolled account cannot map a share or use WinRM, and RDP with NLA stops
working for it. NTLMv2 has no round trip where a server could ask for a code,
so a second factor per SMB connection is impossible. Ristretto uses a gate
instead: you prove your TOTP once, which opens a time window, and network
logons for that account pass until it closes. Duo's remembered sessions work
the same way, without the cloud.

```
ristretto alice            →  TOTP checked, timestamp written
net use \\host\share       →  filter sees a fresh gate, no objection
...5 minutes later...
net use \\host\share       →  gate stale, STATUS_INVALID_WORKSTATION
```

## Limits

Ristretto is a controlled loosening of Doppio's filter. Three limits decide
whether it is any use to you:

1. The window covers the whole account. While a gate is open, anyone who can
   authenticate as that account gets in: password holders, pass-the-hash, a
   well-timed relay. The gate only shows that someone with the phone was at
   this machine recently.
2. You open the gate on the machine it protects, from an elevated session. On
   a headless server that is a deadlock, and an unattended 03:00 backup job
   has nobody to open a gate for it. It fits the case where you already have
   console access and want network access from a second machine for a while.
3. `RunAsPPL` has to be off so Windows loads the unsigned DLL. That also lets
   credential-dumping tools read passwords out of lsass memory. On a machine
   that matters, this is probably a net loss.

If one account needs to reach a share, a separate non-enrolled account with
minimal rights and a long random password is usually the better answer. It
needs no code in lsass and leaves `RunAsPPL` on.

## How it works

| Piece | Runs in | Does |
|---|---|---|
| `RistrettoFilter.dll` | `lsass.exe`, MSV1_0 `Auth0` slot | Vetoes a network logon for an enrolled account unless its gate is fresh |
| `ristretto.exe` | an elevated console | Checks a TOTP through Doppio's `verify.cpp` and writes the gate timestamp |

The filter checks each logon in this order; the first three exits cost at most
one registry read:

```
network logon to this machine? → no  → no objection   (pass-through counts as no)
enforcement on?                → off → no objection
enrolled (RID)?                → no  → no objection   (unreadable index → refuse)
gate fresh?                    → no  → veto
```

The veto is `STATUS_INVALID_WORKSTATION`, the code Doppio's filter returns. In
the Security log a refusal is a failed 4625; expect Sub Status `0xC0000070`,
most likely under Status `0xC000006E` (check both fields in the VM).
`WhichFields`, `UserFlags` and `Authoritative` are written on every path, see
`SECURITY-FIXES.md`, item 15. The enrollment check is Doppio's
`tac::EnrollmentByRid` from `store_index.cpp`, which only reads the index (no
DPAPI, account lookups or heap).

`ristretto.exe` links Doppio's `totp.cpp`, `store.cpp`, `store_index.cpp`,
`verify.cpp` and `statelock.cpp` unmodified, from a pinned submodule, so the
tile and the gate share one failure counter, one `lastStep` and one state
file. Five wrong codes lock the account wherever they were typed, a code used
at one is `Replayed` at the other, and a locked account's code is not checked.
A separate counter would give an attacker a second set of guesses.

> **`ristretto.exe` must sit in the same folder as `TacProvider.dll`.**
> Doppio's `StateLock` builds its lock file path from the calling module's
> directory. Anywhere else gives a second lock file, the tile and the gate can
> then write the state at the same time, and the counter is no longer shared.
> The installer puts it in `C:\Program Files\TheAdminCafe\`.

## Build

From the x64 Native Tools Command Prompt (a plain `cmd` has neither `cl.exe`
nor the SDK headers on the PATH):

```text
git clone https://github.com/Nobrac/Ristretto
cd Ristretto
git submodule update --init --recursive
build-ristretto.bat
```

The filter is built with `/MT /O2 /guard:cf /Qspectre /W4 /WX /sdl` and
linked `/CETCOMPAT /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA`. `/WX` makes a new
warning in lsass code fail the build. `/analyze` runs as a second, advisory
pass.

Tests (Linux, g++, ASan and UBSan; CI runs them on every push) compile the
real filter against fakes for the registry, clock and debugger output. They
cannot show how MSV1_0 really calls the filter, and SEH is mapped to
`try`/`catch`.

```text
make -C tests
```

## Install

Install and enroll Doppio first, and run `enroll /reindex` at least once so
the RID index exists. The installer refuses without it.

```powershell
.\install-ristretto.ps1
```

The installer checks that Doppio is present, the machine is not a domain
controller, LSA protection is off (`RunAsPPL`, `RunAsPPLBoot` and WinInit
event 12 since the last boot), and `Auth0` is empty or belongs to
`TacSubAuth`. It will not take the slot from another product's filter. After
you confirm, it saves the previous `Auth0`, hardens the registry keys before
writing to them, copies `RistrettoFilter.dll` to System32, puts
`ristretto.exe` next to `TacProvider.dll`, and sets `Auth0` last. Reboot to
load the filter.

A second run keeps the config, open gates and saved `Auth0`. If `PrevAuth0`
says `RistrettoFilter` (left behind by an older version), both scripts refuse
to continue and tell you how to fix it.

```text
ristretto <user> [code]     open the network gate (TOTP check)
ristretto /status <user>    show gate state and time remaining
ristretto /close <user>     close the gate now
ristretto /closeall         close every open gate
ristretto /window <sec>     gate lifetime, 30-3600 (default 300)
ristretto /mode gate|off    enforcement kill switch, no reboot
```

Closing a gate stops new logons only. A share or WinRM session opened inside
the window stays up until it disconnects; `Close-SmbSession` on the protected
machine ends SMB sessions.

Pass the code as an argument only in a script. It ends up in the command
line, your shell history and, with command-line process auditing on, 4688
records. The tool warns you when you do it.

First thing to check in the VM: attach a kernel debugger and look for
`[Ristretto]` lines on a network logon. Microsoft documents `Auth0` for domain
controllers; whether MSV1_0 calls it for local accounts on a workstation is
the open question from Part 2. If no lines appear, the filter is loaded but
never called and the gate does nothing.

## Uninstall

```powershell
.\uninstall-ristretto.ps1
```

Reboot, and only then delete `RistrettoFilter.dll` from System32; lsass holds
it until restart. The script restores `Auth0` first, so a failure halfway
leaves the machine on Doppio's filter. It also clears open gates so a later
reinstall cannot find a stale timestamp still inside its window.

## Registry

| Key | Holds |
|---|---|
| `HKLM\SOFTWARE\TheAdminCafe\Ristretto` | `Mode` (kill switch), `WindowSec`, `PrevAuth0` |
| `HKLM\SOFTWARE\TheAdminCafe\Ristretto\Gate` | one `REG_QWORD` per RID: the unix time its gate was opened |
| `HKLM\SOFTWARE\TheAdminCafe\2FA\Rids` | Doppio's enrollment index, read-only to Ristretto |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | `Auth0` = `RistrettoFilter` |

Both Ristretto keys get `D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)` (SYSTEM and
Administrators only, inheritance blocked) at install time, before any value
is written.

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
docs/                       a pointer to the blog article
extern/                     the pinned Doppio submodule
```

Four of the findings in `SECURITY-FIXES.md` were real bugs in the first
draft, three of them copied from code that was safe where it came from.

## Licence

MIT, same as Doppio. See `LICENSE`.
