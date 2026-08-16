@echo off
rem Build the ASM agent: assembles entry.asm with NASM and links a
rem NODEFAULTLIB console exe via MSVC link.exe against the generated
rem kernel32 import library (kernel32.def / kernel32.lib in this folder).
rem
rem Override the linker via FEI_LINK if your MSVC lives elsewhere.
setlocal
cd /d "%~dp0"

set "NASM=C:\Program Files\NASM\nasm.exe"
if "%FEI_LINK%"=="" set "FEI_LINK=E:\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe"

"%NASM%" -f win64 entry.asm -o entry.obj
if errorlevel 1 exit /b 1

"%FEI_LINK%" -NOLOGO -SUBSYSTEM:CONSOLE -ENTRY:_start -NODEFAULTLIB entry.obj kernel32.lib -OUT:agent.exe
if errorlevel 1 exit /b 1

for %%A in (agent.exe) do echo agent.exe built, %%~zA bytes
echo Remember to inject the deployment PSK (tools\inject_psk\inject_psk.py) or
echo generate via the control panel (nasm + link required on the operator box).
endlocal
