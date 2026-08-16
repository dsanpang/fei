#!/bin/sh

# Docker startup script for Fei Distributed Control Platform

echo "Starting Fei Distributed Control Platform..."

# Start NATS server in background
echo "Starting NATS server..."
nats-server -p 4222 &

# Small delay to ensure NATS is ready
sleep 2

# Start the control plane in background
echo "Starting control plane..."
./bin/control-plane &

# Small delay to ensure control plane is ready
sleep 2

# Start the compiler worker in background
echo "Starting compiler worker..."
./bin/compiler-worker &

# Start the gateway in background
echo "Starting gateway..."
./bin/gateway &

# Keep the container running
echo "All components started. Waiting for termination signal..."
wait