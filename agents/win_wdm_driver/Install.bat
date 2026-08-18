@echo off
rem LayeredGuard service install + sample Config rules.
rem Requires an elevated prompt; the .sys must already be signed for the
rem target machine (test-signing mode is enough in a lab VM).

set SERVICE_NAME=LayeredGuard
set DRIVER_PATH=%~dp0Release_x64\LayeredGuard.sys

sc create %SERVICE_NAME% type= filesys start= demand binPath= "%DRIVER_PATH%"

rem MiniFilter Instances (the driver also rewrites these keys itself at
rem load, following the real service name - this keeps them consistent).
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Instances" /v DefaultInstance /t REG_SZ /d "%SERVICE_NAME% Instance" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Instances\%SERVICE_NAME% Instance" /v Altitude /t REG_SZ /d "370030" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Instances\%SERVICE_NAME% Instance" /v Flags /t REG_DWORD /d 0 /f

set CONFIG=HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Config
reg add "%CONFIG%" /v Process /t REG_SZ /d "notepad.exe;test.exe" /f
reg add "%CONFIG%" /v IP      /t REG_SZ /d "192.168.1.100" /f
reg add "%CONFIG%" /v Port    /t REG_SZ /d "8080;3389" /f
reg add "%CONFIG%" /v Path    /t REG_SZ /d "C:\hidden_folder" /f
reg add "%CONFIG%" /v RegPath /t REG_SZ /d "HKLM\SOFTWARE\HiddenKey" /f

sc start %SERVICE_NAME%
