# Windows 2FA, Part 3: Gating Network Logons

*The Admin Cafe · Oct 10, 2026 · Lukas*

*Published at <https://theadmincafe.ch>. Part 1: [Build Your Own 2FA for the
Windows Logon](https://theadmincafe.ch/p/windows-2fa-credential-provider/) ·
Part 2: [Inside LSA](https://theadmincafe.ch/p/windows-2fa-inside-lsa/)*

---

Part 2 ended with a sub-authentication filter that refuses every network logon
for a 2FA-enrolled local account. Correct, and unusable: an enrolled account
can no longer map a share. Part 3 is about the fix — a gate you open once with
a one-time code, and a time window during which SMB, RPC and WinRM pass.

## Foreword

This is the third part, and it is not the one I announced at the end of Part 2.

Back there I wrote that a Part 3 might take on the SSP/AP, done properly:
signed, PPL-compatible, working with Credential Guard instead of poking at it.
That one is still on the list. This is a different article, and it exists
because of a complaint I kept getting about Part 2 — including from myself.

The sub-authentication filter from Part 2 refuses every network logon for an
enrolled account. That is correct behaviour and it is what I asked it to do. It
also means an enrolled account can no longer map a share, can no longer be used
for WinRM, and RDP with NLA stops working. The second factor made the account
safer by making it useless.

So: can an account have 2FA *and* be able to reach `\\host\share`? Not with a
code per connection, as the next chapter explains. But with a gate it works
well enough to be worth building.

The tool is called **Ristretto**. A ristretto is a short shot, the same coffee
with less water. Shorter window, same second factor. It lives in [its own
repository](https://github.com/Nobrac/Ristretto) because it is a companion to
Doppio, not a patch: it needs Doppio installed and enrolled, reads Doppio's RID
index read-only, and links Doppio's `verify.cpp` unmodified.

> **Important:** Same ground rules as Part 2. Throwaway VM, snapshot before
> every reboot, `RunAsPPL` off, BitLocker recovery key within reach, and a
> practised way to edit the registry offline from WinRE. The filter in this
> article replaces the Auth0 slot that Doppio's `TacSubAuth` occupies, so you
> are swapping one unsigned DLL in lsass for another.

As in both earlier parts: the code is in the article, it compiles for x64, and
I will be explicit about what I have and have not run.

## Why there is no second factor per SMB connection

The obvious design is the one that does not work. You would want the server to
ask for a code when a connection comes in, the way the logon tile asks at the
console. There is nowhere to put that question.

NTLMv2 is challenge/response. The server sends a challenge, the client computes
a response from the password hash, the server checks it against the SAM. The
password never crosses the wire, and neither does anything else the user typed.
There is no round trip in that handshake where a server can say "and now a
six-digit code", and no client that would know what to do with it. The protocol
was finished long before anybody wanted a second factor in it.

The sub-authentication filter sits even further from a UI. By the time MSV1_0
calls it, the password is already checked and the only thing left to decide is
yes or no. It gets a SAM record and a logon level. It cannot prompt, it cannot
wait, and anything it does slowly it does on the logon path inside lsass.

So the second factor has to happen **somewhere else, at some other time**, and
the network logon has to be able to look up the result. That is the gate.

## The gate pattern

You prove the second factor once, out of band, and that buys a time window
during which network logons for that account are allowed. Duo calls the same
idea remembered sessions. Ristretto does it without a cloud:

1. `ristretto.exe alice` asks for a one-time code and checks it through
   Doppio's `verify.cpp`.
2. On success it writes a unix timestamp to
   `HKLM\SOFTWARE\TheAdminCafe\Ristretto\Gate\<rid>`, a key with the same
   SYSTEM-and-Administrators ACL Doppio uses for its store.
3. The filter, on every network logon for an enrolled account, reads that one
   value. Fresh enough, no objection. Stale or missing, veto — which is exactly
   what `TacSubAuth` would have done anyway.

The window is 300 seconds by default and clamped to 30–3600.
`ristretto /close alice` shuts it immediately, `/closeall` drops every open
gate, and `/mode off` is a kill switch that takes effect within about five
seconds without a reboot.

Be clear about what that window is. It is **account-wide, not
connection-wide**. While it is open, anyone who can authenticate as that
account gets in — your second laptop, a colleague who knows the password, an
NTLM relay that catches the right moment. The gate proves that somebody with
the phone was at this machine recently. It does not prove that the person on
the other end of this particular SMB connection is that somebody.

That is the whole trade. You get an enrolled account that can still map a
share, and you pay for it with a window in which the second factor is not being
asked for. Five minutes of password-only is a very different thing from
permanent password-only, which is what you had before enrolling, and it is also
a very different thing from the flat deny in Part 2. Pick the one that matches
what you are protecting.

## The decision path

![The filter's decision path: four checks, two outcomes. Only an enrolled
account on a network logon ever reaches the gate
check.](images/filter-decision-path.svg)

Four questions, in that order, on every logon MSV1_0 hands the filter. Three of
them exit to "no objection" and cost one registry read at most; only an
enrolled account on a network logon ever reaches the gate check. The veto is
the same `STATUS_ACCOUNT_RESTRICTION` Doppio's filter returns, so from MSV1_0's
side nothing about the refusal has changed — only the condition in front of it.

## One lockout, not two

The gate tool does not reimplement the code check. It links Doppio's
`totp.cpp`, `store.cpp`, `verify.cpp` and `statelock.cpp` unmodified, as a
pinned submodule. That is not laziness, it is the only way the lockout stays
honest.

If Ristretto kept its own failure counter, an attacker would get two
independent sets of guesses against the same secret — five at the tile and five
at the gate, each with its own doubling lock. Sharing `verify.cpp` means there
is one counter, one `lastStep`, one state file:

- Five wrong codes in a row lock the account, at the tile or at the gate or any
  mix of the two, and the lock doubles 5 → 10 → 20 → 40 → 60 minutes.
- A code burned at the logon screen is `Replayed` at the gate, and the other
  way round.
- While the account is locked the code is not even checked.

There is one deployment detail that makes or breaks this, and it is easy to get
wrong: **`ristretto.exe` has to sit in the same folder as
`TacProvider.dll`.** Doppio's `StateLock` builds its lock file path from the
calling module's own directory. Put the exe somewhere else and you get a second
lock file, which means the tile and the gate can write the state at the same
time, which means the shared counter is no longer shared. The installer copies
it to `C:\Program Files\TheAdminCafe\` for exactly this reason.

### The compromise I made on purpose

`verify.h` says, in so many words, to check the password before the code. Part
1 has a whole chapter on why: if the code comes first, anybody at the logon
screen can lock out every enrolled account by typing garbage.

The gate checks the code **without** a password proof. I went back and forth on
this one.

The argument for doing it anyway: the gate grants nothing by itself. NTLM still
checks the password when the connection is actually made, so an open gate
without the password is worth nothing. And the tool is admin-only three times
over — the state lock file, the State key and the DPAPI secret are all SYSTEM
and Administrators. An attacker who can run it elevated can already turn the
filter off.

The obvious fix is circular, which is what settled it. To prove the password I
would call `LogonUserW` with `LOGON32_LOGON_NETWORK` — and that is a network
logon, which my own filter vetoes while the gate is closed.
`LOGON32_LOGON_INTERACTIVE` would work, but then opening a share gate writes a
4624 type 2 into the Security log every time, which is a lie about what
happened.

So it stays as it is, and the lockout exposure is the price. An elevated
attacker can burn the gate's guesses and lock the account out of its own logon
screen. That is a denial of service by somebody who is already an
administrator, which is a bad day but not a new one.

## Four things my first draft got wrong

I wrote the filter, read it twice, thought it was fine, and then had it
audited. Four findings, and three of them were things I had carried over from
Part 2 without looking at them again. This is the useful part of the article.

### 1. `swprintf_s` can take lsass down

My log lines were built the way Part 2 builds them:

```cpp
WCHAR text[256];
swprintf_s(text, L"Refused a network logon for enrolled account '%s' (RID %lu): "
                 L"no fresh gate (last unlock %lu s ago or none).", name, rid, ageSec);
```

On overflow, `swprintf_s` calls the invalid-parameter handler, and the default
handler **terminates the process**. The process is lsass. That is a bugcheck,
reached from the logon path, which is the one place where a bugcheck can turn
into a boot loop.

It did not overflow. With a 128-character account name that line lands at
roughly 234 of 256 characters, so it worked every time I ran it. It also means
the next person to add three words to the format string ships a machine that
bluescreens on the right username. A safety margin of 22 characters is not a
safety margin, it is a trap with a timer on it.

The formatting now goes through a small bounded appender that truncates and
never calls the CRT:

```cpp
class Buf
{
public:
    Buf(WCHAR* p, SIZE_T cap) : p_(p), cap_(cap), n_(0) { if (cap_) p_[0] = L'\0'; }

    void Str(const WCHAR* s)
    {
        if (!s) return;
        while (*s && n_ + 1 < cap_) p_[n_++] = *s++;
        if (cap_) p_[n_] = L'\0';
    }

    void U64(ULONGLONG v)
    {
        WCHAR t[21]; int i = 0;
        do { t[i++] = (WCHAR)(L'0' + (ULONG)(v % 10)); v /= 10; } while (v && i < 20);
        while (i > 0 && n_ + 1 < cap_) p_[n_++] = t[--i];
        if (cap_) p_[n_] = L'\0';
    }

private:
    WCHAR* p_; SIZE_T cap_; SIZE_T n_;
};
```

A truncated log line is a cosmetic problem. A terminated lsass is not. The same
reasoning took `_time64` out: it drags locale machinery, and locale machinery
touches the heap, in a file whose own header comment says it does not allocate.
`GetSystemTimeAsFileTime` gives the identical value with none of that.

### 2. The `catch (...)` never worked

Part 2's filter ends with a catch-all, and so did mine:

```cpp
catch (...)
{
    // Nothing above allocates; if that ever changes: fail closed.
}
```

With `/EHsc` — which is in the build line of both articles — a C++
`catch (...)` does **not** catch SEH exceptions. An access violation walks
straight past it. And an access violation is the realistic failure here: the
one pointer we dereference is a `UNICODE_STRING` handed in by the caller.

So the handler covered `std::bad_alloc`, in a function with no allocations, and
nothing else. It was commentary, not a safety net.

The fix is `__try` / `__except`, which does catch it. `__try` cannot share a
frame with objects that need unwinding, so the decision moved into its own
function and the export is just the wrapper:

```cpp
__try
{
    result = Decide(UserAll);
}
__except (EXCEPTION_EXECUTE_HANDLER)
{
    Report(EVENTLOG_ERROR_TYPE, 303,
           L"Unhandled exception while deciding a network logon - refusing (fail closed).");
    result = STATUS_ACCOUNT_RESTRICTION;
}
```

Catching an access violation and carrying on is normally a bad idea, because
you do not know what state you are in. Inside lsass the alternative is a
bugcheck, so refusing one logon and staying up is the better of two bad
options. It reduces the risk. It does not remove it.

### 3. The enrollment check failed open

This is the one that actually mattered, and it is four lines copied from
`store.cpp`:

```cpp
return RegGetValueW(HKEY_LOCAL_MACHINE, kDoppioRids, value,
                    RRF_RT_REG_DWORD, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
```

Every failure becomes `false`, `false` means not enrolled, and not enrolled
means `STATUS_SUCCESS`. One unexpected registry error and an enrolled account
walks past the gate. In `store.cpp` that is defensible, because the credential
provider has other checks behind it. In a filter whose entire job is the veto,
"I could not tell" must not come out as "yes".

It is three outcomes now, not two:

| What the registry says | What the filter does |
| --- | --- |
| `Rids` key missing entirely | allow — Doppio is not installed, nothing of ours to enforce |
| value missing | allow — genuinely not enrolled |
| anything else | refuse that one account |

The first row is deliberate and it is the only one I am still slightly unhappy
with. Failing closed there would deny *every* network logon on the machine the
moment somebody uninstalls Doppio, and a security tool that bricks file sharing
on removal is a tool people rip out angrily. So a missing index is permissive
and a broken read is not.

### 4. `WindowSec` had no ceiling

The config read accepted any non-zero DWORD:

```cpp
if (RegGetValueW(..., L"WindowSec", ..., &v, &cb) == ERROR_SUCCESS && v)
    g_windowSec = v;
```

`0xFFFFFFFF` seconds is about 136 years. A typo in regedit turns the gate into
a door that is propped open for the rest of the machine's life, and nothing
anywhere says so. The key is admin-only, so this is not a privilege boundary —
it is an admin handing themselves a silent permanent bypass and believing the
opposite.

It is clamped to 30–3600 now, on **both** sides: in `ristretto.exe /window`
when writing, and in the filter when reading. Only the second one matters.
Clamping on write is a courtesy to the person using the tool; clamping on read
is what holds when the value did not come from the tool.

There were four smaller ones too — unsynchronised config globals, account names
going to `OutputDebugStringW` on every allowed SMB connection, an installer
that stored `PrevAuth0 = 'TacSubAuth'` when there had been no `Auth0` at all
(so uninstalling pointed lsass at a DLL that was never there), and a config key
left on inherited permissions while holding the enforcement kill switch. They
are all in `SECURITY-FIXES.md` in the repo.

The pattern across all four of the big ones is the same, and it is the same
lesson as Part 2 from a different angle. Part 2 taught me to check what Windows
expects from my code. This round taught me that code copied from a place where
it was safe does not arrive safe. `swprintf_s`, the catch-all and the
enrollment read were all fine where they came from. What changed was the blast
radius.

## Limits

Same chapter as the earlier parts, and it is the one to read if you read
nothing else.

- **The window is account-wide.** While a gate is open, anyone who can
  authenticate as that account gets in, not only the person who opened it.
  Password holders, pass-the-hash, a well-timed relay. Shorter windows shrink
  the exposure, they do not change its shape.
- **The gate is opened on the machine it protects, elevated.** This is the
  limit that decides whether Ristretto is any use to you, and I did not see it
  until somebody asked me what the thing is actually *for*. You need an
  interactive session on the box to unlock network access *to* the box. On a
  headless server you reach mainly over the network, that is a deadlock: you
  cannot get in to open the gate that would let you in. Unattended access has
  the same problem from the other side — a backup job that pulls the share at
  03:00 arrives as a network logon, and nobody is awake to open a gate for it.
  It also takes most of the RDP argument away: if you have no session yet, you
  cannot unlock the one that NLA needs. What is left is the case where you
  already have console or physical access and want network access from a second
  machine for a while. That is a real case. It is a narrow one.
- **No second factor is checked at connection time.** None. That is the
  premise, not a bug — see the NTLM chapter.
- **`RunAsPPL` has to be off**, which is a real downgrade. PPL is what stops
  credential-dumping tools reading lsass memory. Turning it off to load an
  unsigned filter trades a strong, broad mitigation for a narrow one. On a
  machine that matters, that trade is probably negative. This stays test-VM
  code until the DLL is signed and PPL can stay on.
- **A fault in the filter is a bugcheck.** The `__except` helps. It does not
  make lsass-resident code safe.
- **Whether MSV1_0 calls the filter for local accounts is still the open
  question from Part 2.** Microsoft documents `Auth0` for domain controllers.
  If you never see a `[Ristretto]` line in the debugger, the filter is loaded
  and never asked, and the gate is decorative.
- **Batch, service, `runas` and UAC are untouched**, exactly as in Part 2. Keep
  the deny rights on for those.
- **The gate tool checks the code without a password.** Covered above. An
  elevated attacker can burn the shared lockout.
- **Clock changes close the gate, never open it.** A clock moved back reads as
  skew and the filter treats it as closed; moved forward, the gate expires
  early. Both directions fail closed, which also means an NTP correction or a
  VM snapshot restore can shut a gate you just opened.
- **Nothing is tested on a live LSA.** It compiles for x64, it exports the one
  symbol, and the decision path allocates nothing. That is the same honest
  position Part 2 ended on, and it has not improved.

And the one that is not a limit of this code but of the idea: if you want an
actual second factor on every network logon, the gate is not it. That lives in
the SSP/AP, done properly, which is still the part I owe you.

## Build and install

Prerequisites are Part 2's, plus a working Doppio: installed, enrolled, and
`enroll /reindex` run at least once so the RID index exists. Ristretto reads
that index and will not install without it.

```text
git clone https://github.com/Nobrac/Ristretto
cd Ristretto
git submodule update --init --recursive
build-ristretto.bat
```

From the x64 Native Tools Command Prompt, as always. The submodule is a pinned
Doppio, deliberately: a breaking change on Doppio's side fails this build
loudly instead of drifting quietly.

Then, from an elevated PowerShell, after a snapshot:

```powershell
.\install-ristretto.ps1
```

It checks that Doppio is there, that `RunAsPPL` is off, and that `Auth0`
belongs to `TacSubAuth` or to nobody — it will not take the slot from another
product's filter. It saves what was there, copies `RistrettoFilter.dll` to
System32, puts `ristretto.exe` next to `TacProvider.dll`, and sets `Auth0`
last, once the DLL is actually on disk. Then it asks you to confirm before any
of that happens, because you are putting an unsigned DLL in the logon path.
Reboot to load it.

```text
ristretto <user> [code]     open the network gate (TOTP check)
ristretto /status <user>    show gate state and time remaining
ristretto /close <user>     close the gate now
ristretto /closeall         close every open gate
ristretto /window <sec>     gate lifetime, 30-3600 (default 300)
ristretto /mode gate|off    enforcement kill switch, no reboot
```

A session looks like this: `ristretto alice`, type the code from the phone,
then `net use \\host\share` works for the next five minutes.
`ristretto /status alice` tells you how long is left. Pass the code as an
argument only in a script — it ends up in the command line, in 4688 records and
in your shell history, and the tool says so when you do it.

First thing to check in the VM, same as Part 2: attach the kernel debugger and
watch for `[Ristretto]` lines on a network logon. No lines means MSV1_0 is not
calling the filter on your build, and everything above is theatre.

Uninstalling is `.\uninstall-ristretto.ps1`, then a reboot, *then* delete the
DLL from System32. It restores `Auth0` first, so a failure halfway through
leaves the machine on Doppio's filter rather than on nothing.

## Where this goes next

Three parts in, local Windows accounts have a second factor at the console
(Part 1), a veto inside LSA for everything that does not reach the tile (Part
2), and a way to open the network path again without giving up the factor
entirely (this one). None of it is production code and all of it is a way to
learn the layer.

What I would build next, roughly in order of how much I want it:

- **Sign the DLL.** Everything about `RunAsPPL` off goes away, and the whole
  project stops being a VM exercise. This is the real blocker.
- **The SSP/AP, properly.** Still the Part 3 I promised at the end of Part 2:
  signed, PPL-compatible, working with Credential Guard, making an enforcement
  decision and never keeping a credential. The gate exists because that one is
  hard, not instead of it.
- **Push approval instead of a gate.** A connection that waits a few seconds
  for a tap on the phone is a real per-connection second factor. It needs a
  service and somewhere to send the push, and the filter cannot block on the
  logon path, so the shape of it is not obvious. Interesting problem.
- **Bind the window to something.** I looked at binding a gate to the client
  workstation name from `NETLOGON_NETWORK_INFO`. The client supplies that name
  and can write anything in it, so it would look like a control and be none.
  Left out on purpose.

## Sources

- [Part 1: Build Your Own 2FA for the Windows Logon](https://theadmincafe.ch/p/windows-2fa-credential-provider/)
- [Part 2: Inside LSA](https://theadmincafe.ch/p/windows-2fa-inside-lsa/)
- [Doppio on GitHub](https://github.com/Nobrac/Doppio) — the credential
  provider, the store and `verify.cpp`
- [Ristretto on GitHub](https://github.com/Nobrac/Ristretto) — this article,
  plus `SECURITY-FIXES.md`
- [`Msv1_0SubAuthenticationFilter`](https://learn.microsoft.com/en-us/windows/win32/api/subauth/nf-subauth-msv1_0subauthenticationfilter)
  — Microsoft's reference for the `Auth0` hook
- [Configuring additional LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
  — what `RunAsPPL` is and what turning it off costs you

MIT licensed, same as Doppio. If you build on it, or if you find the fifth
thing I got wrong, I'd like to hear about it.
