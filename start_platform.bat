@echo off
setlocal

echo 启动 FEI 分布式测控平台 v3.0.0
echo ==============================================

REM 检查是否安装了必要的组件
echo 检查依赖项...

where go >nul 2>&1
if %errorlevel% neq 0 (
    echo 错误: 未找到 Go。请先安装 Go 1.21+
    pause
    exit /b 1
)

where rustc >nul 2>&1
if %errorlevel% neq 0 (
    echo 警告: 未找到 Rust。某些功能可能不可用。
)

where node >nul 2>&1
if %errorlevel% neq 0 (
    echo 警告: 未找到 Node.js。前端功能可能不可用。
)

echo 所有依赖项检查完成。
echo.

REM 创建日志目录
if not exist logs mkdir logs

REM 启动NATS服务器
echo 启动 NATS 服务器...
start /min nats-server -p 4222 -log_file logs\nats.log
echo NATS 服务器已在后台启动。
echo.

REM 启动控制面组件
echo 启动控制面核心...
cd control-plane\go_core
start /min go run main.go > ..\..\logs\control_plane.log 2>&1
echo 控制面核心已在后台启动。
cd ..\..

echo 启动编译器工作器...
cd control-plane\compiler_worker
start /min go run main.go > ..\..\logs\compiler_worker.log 2>&1
echo 编译器工作器已在后台启动。
cd ..\..

REM 启动网关组件
echo 启动网关...
cd gateway\go_gateway
start /min go run main.go > ..\..\logs\gateway.log 2>&1
echo 网关已在后台启动。
cd ..\..

echo 启动NATS总线...
cd gateway\nats_bus
start /min go run main.go > ..\..\logs\nats_bus.log 2>&1
echo NATS总线已在后台启动。
cd ..\..

echo.
echo ==============================================
echo FEI 分布式测控平台已启动！
echo 
echo 服务状态:
echo - NATS 服务器: localhost:4222
echo - 网关: localhost:4433
echo - 控制面: localhost:8080 (待实现)
echo 
echo 日志文件位于 logs/ 目录
echo 按任意键关闭所有服务...
pause >nul

REM 关闭所有启动的服务
echo 关闭 FEI 平台服务...
taskkill /f /im nats-server.exe 2>nul
taskkill /f /im go.exe 2>nul
echo 所有服务已关闭。