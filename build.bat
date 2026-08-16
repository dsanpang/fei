@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "BIN=%ROOT%bin"
if not exist "%BIN%" mkdir "%BIN%"

echo ========================================
echo  FEI Platform Build (Windows)
echo ========================================

where go >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] go not found in PATH
    exit /b 1
)

echo.
echo [1/5] Building certgen...
cd /d "%ROOT%tools\certgen"
go build -o "%BIN%\certgen.exe" .
if !ERRORLEVEL! neq 0 (echo FAIL: certgen & exit /b 1)
echo OK

echo.
echo [2/5] Building gateway...
cd /d "%ROOT%gateway\go_gateway"
go build -o "%BIN%\gateway.exe" .
if !ERRORLEVEL! neq 0 (echo FAIL: gateway & exit /b 1)
echo OK

echo.
echo [3/5] Building control-plane...
cd /d "%ROOT%control-plane\go_core"
go build -o "%BIN%\control_plane.exe" .
if !ERRORLEVEL! neq 0 (echo FAIL: control-plane & exit /b 1)
echo OK

echo.
echo [4/5] Building nats-bus...
cd /d "%ROOT%gateway\nats_bus"
go build -o "%BIN%\nats_bus.exe" .
if !ERRORLEVEL! neq 0 (echo FAIL: nats-bus & exit /b 1)
echo OK

echo.
echo [5/5] Building compiler-worker...
cd /d "%ROOT%control-plane\compiler_worker"
go build -o "%BIN%\compiler_worker.exe" .
if !ERRORLEVEL! neq 0 (echo FAIL: compiler-worker & exit /b 1)
echo OK

echo.
echo ========================================
echo  Generating TLS certificates...
echo ========================================
if not exist "%ROOT%certs\psk.bin" (
    "%BIN%\certgen.exe" "%ROOT%certs"
) else (
    echo Certificates already exist in %ROOT%certs\
)

echo.
echo ========================================
echo  Running gateway tests...
echo ========================================
cd /d "%ROOT%gateway\go_gateway"
go test -v -count=1 ./...

echo.
echo ========================================
echo  Build complete! Outputs in: %BIN%
echo ========================================
cd /d "%ROOT%"
