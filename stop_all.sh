#!/bin/bash

PROJECT_DIR=~/os-command-injection-ml
cd $PROJECT_DIR

echo "🛑 Stopping ML Command Detection System..."

# Stop ML Server
if [ -f logs/ml_server.pid ]; then
    ML_PID=$(cat logs/ml_server.pid)
    if ps -p $ML_PID > /dev/null; then
        kill $ML_PID
        echo "✅ ML Server stopped (PID: $ML_PID)"
    else
        echo "⚠️  ML Server not running"
    fi
    rm logs/ml_server.pid
fi

# Stop MCP Bridge
if [ -f logs/mcp_bridge.pid ]; then
    BRIDGE_PID=$(cat logs/mcp_bridge.pid)
    if ps -p $BRIDGE_PID > /dev/null; then
        kill $BRIDGE_PID
        echo "✅ MCP Bridge stopped (PID: $BRIDGE_PID)"
    else
        echo "⚠️  MCP Bridge not running"
    fi
    rm logs/mcp_bridge.pid
fi

echo "✅ All services stopped"

