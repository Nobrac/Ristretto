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
cl /nologo /LD /MT /O2 /guard:cf /Qspectre /EHsc /std:c++17 /W4 /WX /sdl /analyze ^
   /DUNICODE /D_UNICODE ^
   src\ristretto_filter.cpp /Fe:RistrettoFilter.dll ^
   /link /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA ^
   /DEF:src\RistrettoFilter.def advapi32.lib
if errorlevel 1 goto :fail

cl /nologo /MT /O2 /guard:cf /Qspectre /EHsc /std:c++17 /W4 /sdl /analyze ^
   /DUNICODE /D_UNICODE ^
   /I%DOPPIO% src\ristretto.cpp %DOPPIO%\totp.cpp %DOPPIO%\store.cpp ^
   %DOPPIO%\verify.cpp %DOPPIO%\statelock.cpp /Fe:ristretto.exe ^
   /link /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA ^
   bcrypt.lib crypt32.lib advapi32.lib
if errorlevel 1 goto :fail

del /q *.obj *.exp 2>nul
echo Built RistrettoFilter.dll and ristretto.exe
goto :eof
:fail
echo BUILD FAILED
exit /b 1
