#!/bin/bash

# fei_monitor.sh - FEI平台监控脚本

echo "FEI 分布式测控平台监控"
echo "========================"

# 检查进程
echo "正在运行的 FEI 相关进程:"
ps aux | grep -E "(nats-server|go run|fei)" | grep -v grep

echo ""
echo "端口监听状态:"
netstat -tulpn 2>/dev/null | grep -E ":(4433|8080|4222)" || echo "无法获取端口信息 (可能需要管理员权限)"

echo ""
echo "系统资源使用情况:"
if command -v top >/dev/null 2>&1; then
    echo "CPU/MEM 使用率最高的进程:"
    ps aux --sort=-%cpu | head -10
elif command -v wmic >/dev/null 2>&1; then
    echo "Windows 系统信息:"
    wmic cpu get LoadPercentage
    wmic OS get TotalVisibleMemorySize,FreePhysicalMemory
fi

echo ""
echo "日志文件大小:"
if [ -d "logs" ]; then
    du -sh logs/*
else
    echo "logs 目录不存在"
fi

echo ""
echo "磁盘使用情况:"
df -h . 2>/dev/null || echo "无法获取磁盘信息"

echo ""
echo "监控完成。"