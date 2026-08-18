@echo off
rem One-time test-signing certificate setup (run as Administrator on the
rem lab VM host, NOT on any production machine).
rem After this script: build the driver (PostBuild signs automatically),
rem then `bcdedit /set testsigning on` and reboot once.

makecert -r -pe -ss PrivateCertStore -n "CN=LayeredGuardTestCert" LayeredGuardTestCert.cer
if errorlevel 1 goto :err

certmgr -add LayeredGuardTestCert.cer -s -r localMachine Root
certmgr -add LayeredGuardTestCert.cer -s -r localMachine TrustedPublisher
if errorlevel 1 goto :err

echo Certificate installed. Now run: bcdedit /set testsigning on  (then reboot)
goto :eof

:err
echo makecert/certmgr failed - are the WDK bin directories on PATH?
