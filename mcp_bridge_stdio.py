#!/usr/bin/env python3
"""MCP stdio bridge for ML command injection detector"""
import json
import sys
import requests
from typing import Any, Dict

ML_SERVER = "http://127.0.0.1:8000"

def send_response(response: Dict[str, Any]) -> None:
    """Send JSON-RPC response to stdout"""
    print(json.dumps(response), flush=True)

def handle_request(request: Dict[str, Any]) -> None:
    """Handle incoming JSON-RPC request"""
    method = request.get("method")
    req_id = request.get("id")
    params = request.get("params", {})
    
    try:
        if method == "initialize":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "ml-command-detector",
                        "version": "1.0.0"
                    }
                }
            })
        
        elif method == "tools/list":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "analyze_command",
                            "description": "Analyze shell commands for OS command injection vulnerabilities using ML",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "commands": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "description": "List of commands to analyze"
                                    }
                                },
                                "required": ["commands"]
                            }
                        },
                        {
                            "name": "check_health",
                            "description": "Check ML backend health status",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        }
                    ]
                }
            })
        
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            if tool_name == "check_health":
                try:
                    resp = requests.get(f"{ML_SERVER}/health", timeout=5)
                    health_data = resp.json()
                    send_response({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": f"ML Backend: {health_data['status']}\nModel loaded: {health_data['model_loaded']}"
                            }]
                        }
                    })
                except Exception as e:
                    send_response({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32603,
                            "message": f"Health check failed: {str(e)}"
                        }
                    })
            
            elif tool_name == "analyze_command":
                commands = arguments.get("commands", [])
                if not commands:
                    send_response({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32602,
                            "message": "Missing required parameter: commands"
                        }
                    })
                    return
                
                try:
                    resp = requests.post(
                        f"{ML_SERVER}/analyze",
                        json={"commands": commands},
                        timeout=10
                    )
                    results = resp.json()
                    
                    # Format results
                    output_lines = ["## Command Injection Analysis\n"]
                    for r in results:
                        status_emoji = "🚫" if r["is_malicious"] else "✅"
                        output_lines.append(f"{status_emoji} **{r['command']}**")
                        output_lines.append(f"  - Malicious: {r['is_malicious']}")
                        output_lines.append(f"  - Confidence: {r['confidence']:.2%}")
                        output_lines.append(f"  - Severity: {r['severity']}")
                        if r["risk_factors"]:
                            output_lines.append(f"  - Risk factors: {', '.join(r['risk_factors'])}")
                        output_lines.append("")
                    
                    send_response({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": "\n".join(output_lines)
                            }]
                        }
                    })
                except Exception as e:
                    send_response({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32603,
                            "message": f"Analysis failed: {str(e)}"
                        }
                    })
            else:
                send_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Unknown tool: {tool_name}"
                    }
                })
        
        else:
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            })
    
    except Exception as e:
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        })

def main():
    """Main stdio loop"""
    # Log to stderr for debugging
    print("MCP ML Command Detector Bridge starting...", file=sys.stderr, flush=True)
    
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        
        try:
            request = json.loads(line)
            print(f"Received: {request.get('method')}", file=sys.stderr, flush=True)
            handle_request(request)
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr, flush=True)

if __name__ == "__main__":
    main()
