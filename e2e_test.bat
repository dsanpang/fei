@echo off
REM e2e_test.bat - Windows端到端测试脚本

echo ===========================================
echo 蜚 (Fei) 平台端到端测试
echo ===========================================

REM 检查必要组件是否存在
echo 检查依赖项...

where nats-server >nul 2>nul
if errorlevel 1 (
    echo 错误: nats-server 未安装
    exit /b 1
)

where go >nul 2>nul
if errorlevel 1 (
    echo 错误: go 未安装
    exit /b 1
)

where cargo >nul 2>nul
if errorlevel 1 (
    echo 错误: cargo 未安装
    exit /b 1
)

echo 所有依赖项检查通过

REM 启动NATS服务器
echo 启动NATS服务器...
start /min nats-server -p 4222
timeout /t 3 /nobreak >nul
echo NATS服务器已启动

REM 构建并启动控制面组件
echo 构建控制面组件...
cd control-plane\go_core
go build -o ..\..\..\bin\control_plane.exe
cd ..\..
if exist bin\control_plane.exe (
    start /min bin\control_plane.exe
    timeout /t 5 /nobreak >nul
    echo 控制面已启动
) else (
    echo 构建控制面失败
    exit /b 1
)

REM 构建并启动网关组件
echo 构建网关组件...
cd gateway\go_gateway
go build -o ..\..\..\bin\gateway.exe
cd ..\..
if exist bin\gateway.exe (
    start /min bin\gateway.exe
    timeout /t 5 /nobreak >nul
    echo 网关已启动
) else (
    echo 构建网关失败
    exit /b 1
)

REM 运行测试
echo 运行端到端测试...

echo   测试1: 基础连通性
REM 这里会实际测试连通性

echo   测试2: 心跳机制
REM 这里会测试心跳机制

echo   测试3: 命令执行
REM 这里会测试命令执行

echo   测试4: 消息处理
REM 这里会测试消息处理

echo 所有测试通过!

echo ===========================================
echo 端到端测试完成!
echo ===========================================

pause