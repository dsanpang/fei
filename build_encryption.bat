@echo off
setlocal

echo 构建 FEI 平台加密模块
echo.

if "%1" == "" goto usage
if "%1" == "encrypt" goto build_encrypt
if "%1" == "test" goto build_test
goto usage

:build_encrypt
echo 构建加密模块...
if not exist bin mkdir bin
gcc -c encryption.c -o bin/encryption.o
if %errorlevel% equ 0 (
    echo 加密模块构建成功
) else (
    echo 加密模块构建失败
    exit /b 1
)
goto :eof

:build_test
echo 构建加密测试程序...
if not exist bin mkdir bin
gcc test_encryption.c encryption.c -o bin/test_encryption.exe
if %errorlevel% equ 0 (
    echo 测试程序构建成功
    echo 运行测试程序...
    bin\test_encryption.exe
) else (
    echo 测试程序构建失败
    exit /b 1
)
goto :eof

:usage
echo 使用方法:
echo   %0 encrypt  - 构建加密模块
echo   %0 test     - 构建并运行测试程序
goto :eof