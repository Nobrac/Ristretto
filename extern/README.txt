The Doppio sources live here as a pinned git submodule:

    git submodule add https://github.com/Nobrac/Doppio extern/doppio
    git submodule update --init --recursive

ristretto.exe links totp.cpp, store.cpp, store_index.cpp, verify.cpp and
statelock.cpp from this tree, unmodified. RistrettoFilter.dll links one file,
store_index.cpp: the enrollment index reads, without DPAPI or account
lookups, so it is safe inside lsass. The tests in ../tests also use Doppio's
test shims and fakes from tests/native. The pin is deliberate: a breaking
change on Doppio's side fails this build loudly instead of drifting silently.

Pinned at Doppio 37a827d (the merge of Doppio's second review). Before that,
2776655.

What the pin does NOT catch is a semantic change behind an unchanged
signature. If Doppio's VerifyOtp or EnrollmentByRid keeps its prototype but
changes what a result means, this builds and links cleanly and behaves
differently. One place in this repo still duplicates Doppio logic by hand -
see SECURITY-FIXES.md, item 14:

  * OpenProtected  in src/ristretto.cpp  <- store.cpp's OpenProtectedKey
                                            (copied from 2776655; Doppio's
                                            version has diverged on purpose)

When you move the pin, read the diff of store.cpp, store_index.cpp and
verify.cpp before you trust the build, and run make -C tests.
