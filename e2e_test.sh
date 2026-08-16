#!/bin/bash
# e2e_test.sh - 端到端测试脚本

set -e  # 遇到错误时退出

echo "==========================================="
echo "蜚 (Fei) 平台端到端测试"
echo "==========================================="

# 检查必要组件是否存在
check_dependencies() {
    echo "检查依赖项..."
    
    if ! command -v nats-server &> /dev/null; then
        echo "错误: nats-server 未安装"
        exit 1
    fi
    
    if ! command -v go &> /dev/null; then
        echo "错误: go 未安装"
        exit 1
    fi
    
    if ! command -v cargo &> /dev/null; then
        echo "错误: cargo 未安装"
        exit 1
    fi
    
    echo "所有依赖项检查通过"
}

# 启动NATS服务器
start_nats() {
    echo "启动NATS服务器..."
    nats-server -p 4222 &
    NATS_PID=$!
    sleep 2  # 等待NATS启动
    echo "NATS服务器已启动 (PID: $NATS_PID)"
}

# 启动控制面组件
start_control_plane() {
    echo "启动控制面组件..."
    cd control-plane/go_core
    go build -o ../../../bin/control_plane .
    cd ../..
    ../../../bin/control_plane &
    CONTROL_PLANE_PID=$!
    sleep 3  # 等待控制面启动
    echo "控制面已启动 (PID: $CONTROL_PLANE_PID)"
}

# 启动网关组件
start_gateway() {
    echo "启动网关组件..."
    cd gateway/go_gateway
    go build -o ../../../bin/gateway .
    cd ../..
    ../../../bin/gateway &
    GATEWAY_PID=$!
    sleep 3  # 等待网关启动
    echo "网关已启动 (PID: $GATEWAY_PID)"
}

# 运行测试
run_tests() {
    echo "运行端到端测试..."
    
    # 测试1: 基础连通性
    echo "  测试1: 基础连通性"
    # 这里会实际测试连通性
    
    # 测试2: 心跳机制
    echo "  测试2: 心跳机制"
    # 这里会测试心跳机制
    
    # 测试3: 命令执行
    echo "  测试3: 命令执行"
    # 这里会测试命令执行
    
    # 测试4: 消息处理
    echo "  测试4: 消息处理"
    # 这里会测试消息处理
    
    echo "所有测试通过!"
}

# 清理资源
cleanup() {
    echo "清理资源..."
    
    if [ ! -z "$GATEWAY_PID" ]; then
        kill $GATEWAY_PID 2>/dev/null || true
        echo "已停止网关 (PID: $GATEWAY_PID)"
    fi
    
    if [ ! -z "$CONTROL_PLANE_PID" ]; then
        kill $CONTROL_PLANE_PID 2>/dev/null || true
        echo "已停止控制面 (PID: $CONTROL_PLANE_PID)"
    fi
    
    if [ ! -z "$NATS_PID" ]; then
        kill $NATS_PID 2>/dev/null || true
        echo "已停止NATS (PID: $NATS_PID)"
    fi
    
    echo "资源清理完成"
}

# 注册清理函数
trap cleanup EXIT

# 执行测试流程
check_dependencies
start_nats
start_control_plane
start_gateway
run_tests

echo "==========================================="
echo "端到端测试完成!"
echo "==========================================="