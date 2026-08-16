@echo off
setlocal enabledelayedexpansion

echo ========================================
echo Building ASM Agent for Windows x64
echo ========================================

set NASM=C:\Program Files\NASM\nasm.exe
set LLD_LINK=C:\Program Files\LLVM\bin\lld-link.exe
set SDK_LIB=E:\Windows Kits\10\Lib\10.0.22621.0\um\x64

if not exist "%NASM%" (
    echo ERROR: NASM not found
    exit /b 1
)
if not exist "%LLD_LINK%" (
    echo ERROR: lld-link not found
    exit /b 1
)
if not exist "%SDK_LIB%\kernel32.lib" (
    echo ERROR: kernel32.lib not found
    exit /b 1
)

echo [1/3] Assembling entry.asm...
"%NASM%" -f win64 -w-all -o entry.obj entry.asm
if %ERRORLEVEL% neq 0 (
    echo ERROR: Assembly failed
    exit /b 1
)

echo [2/3] Linking agent.exe with lld-link...
"%LLD_LINK%" /ENTRY:_start /SUBSYSTEM:CONSOLE /NODEFAULTLIB /LIBPATH:"%SDK_LIB%" kernel32.lib ws2_32.lib /OUT:agent.exe entry.obj
if %ERRORLEVEL% neq 0 (
    echo ERROR: Linking failed
    exit /b 1
)

echo [3/3] Verifying size constraint...
for %%F in (agent.exe) do set SIZE=%%~zF
echo Agent size: !SIZE! bytes

if !SIZE! gtr 15360 (
    echo WARNING: Agent exceeds 15KB limit ^(!SIZE! ^> 15360^)
) else (
    echo SUCCESS: Agent meets size requirement
)

del entry.obj 2>nul
echo Build complete!
