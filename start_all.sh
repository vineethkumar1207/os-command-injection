#!/bin/bash

echo "🚀 Starting ML Command Detection System..."

# Start ML Server
echo "Starting ML Server on port 8000..."
cd ~/os-command-injection-ml
python3 ml_server.py > ml_server.log 2>&1 &
ML_PID=$!
echo "ML Server PID: $ML_PID"

# Wait for ML server to start
sleep 3

# Start MCP Bridge
echo "Starting MCP Bridge on port 8002..."
python3 mcp_bridge.py > mcp_bridge.log 2>&1 &
BRIDGE_PID=$!
echo "MCP Bridge PID: $BRIDGE_PID"

# HexStrike AI should already be running
echo "✅ All services started!"
echo "ML Server: http://localhost:8000"
echo "MCP Bridge: http://localhost:8002"
echo "HexStrike AI: http://localhost:8001"

echo ""
echo "To stop services:"
echo "  kill $ML_PID $BRIDGE_PID"
echo ""
echo "View logs:"
echo "  tail -f ml_server.log"
echo "  tail -f mcp_bridge.log"
