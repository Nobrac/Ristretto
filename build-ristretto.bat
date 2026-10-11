@echo off
setlocal
set DOPPIO=extern\doppio

if not exist %DOPPIO%\verify.cpp (
    echo Doppio sources missing. Run: git submodule update --init --recursive
    exit /b 1
)

rem The filter runs inside lsass: /Qspectre and /guard:cf are not optional
rem there, and /MT keeps a CRT DLL dependency out of the logon path.
rem /WX so a new warning in lsass-resident code fails the build.
rem
rem Two separate passes, on purpose.
rem
rem The pass that produces the binaries treats COMPILER warnings as errors
rem (/W4 /WX). That is the right bar for code that runs inside lsass.
rem
rem /analyze is a different thing: a deeper static analyser that reasons about
rem pointers and buffers. It finds real bugs, and it also reports things that
rem are correct but that it cannot prove across a call, plus deliberate
rem constructs like an SEH filter. Those are worth reading. They are not worth
rem failing a build over, and the Windows SDK's own headers raise some of them
rem (C28301, a PNTSTATUS annotation mismatch between bcrypt.h and ntsecapi.h).
rem So analysis runs afterwards, advisory, and its findings do not stop the
rem build. Read them; do not ignore them.

cl /nologo /LD /MT /O2 /guard:cf /Qspectre /EHsc /std:c++17 /W4 /WX /sdl ^
   /DUNICODE /D_UNICODE ^
   src\ristretto_filter.cpp /Fe:RistrettoFilter.dll ^
   /link /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA ^
   /DEF:src\RistrettoFilter.def advapi32.lib
if errorlevel 1 goto :fail

cl /nologo /MT /O2 /guard:cf /Qspectre /EHsc /std:c++17 /W4 /WX /sdl ^
   /DUNICODE /D_UNICODE ^
   /I%DOPPIO% src\ristretto.cpp %DOPPIO%\totp.cpp %DOPPIO%\store.cpp ^
   %DOPPIO%\verify.cpp %DOPPIO%\statelock.cpp /Fe:ristretto.exe ^
   /link /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA ^
   bcrypt.lib crypt32.lib advapi32.lib
if errorlevel 1 goto :fail

echo.
echo === Static analysis (advisory - does not fail the build) ===
cl /nologo /c /analyze /analyze:only /analyze:external- ^
   /external:anglebrackets /external:W0 /wd28301 ^
   /EHsc /std:c++17 /W4 /DUNICODE /D_UNICODE /I%DOPPIO% ^
   src\ristretto_filter.cpp src\ristretto.cpp
echo === End of analysis ===
rem Clear whatever the analysis pass left in errorlevel. Its findings are
rem advisory, and the caller checks this script's exit code to decide whether
rem the build worked - which it did, above.
ver >nul
echo.

del /q *.obj *.exp 2>nul
echo Built RistrettoFilter.dll and ristretto.exe
goto :eof
:fail
echo BUILD FAILED
exit /b 1
