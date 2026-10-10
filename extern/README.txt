The Doppio sources live here as a pinned git submodule:

    git submodule add https://github.com/Nobrac/Doppio extern/doppio
    git submodule update --init --recursive

ristretto.exe links totp.cpp, store.cpp, verify.cpp and statelock.cpp from
this tree, unmodified. The pin is deliberate: a breaking change on Doppio's
side fails this build loudly instead of drifting silently.

What the pin does NOT catch is a semantic change behind an unchanged
signature. If Doppio's VerifyOtp keeps its prototype but changes what a
result means, this builds and links cleanly and behaves differently. Two
places in this repo duplicate Doppio logic by hand and have the same
exposure - see SECURITY-FIXES.md, "Duplicated logic":

  * EnrollmentOf   in src/ristretto_filter.cpp  <- tac::IsEnrolledByRid
  * OpenProtected  in src/ristretto.cpp         <- store.cpp's OpenProtectedKey

When you move the pin, read the diff of store.cpp and verify.cpp before you
trust the build.
