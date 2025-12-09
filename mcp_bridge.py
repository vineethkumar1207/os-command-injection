from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
import requests
import json

app = FastAPI(title="MCP Bridge for Copilot Integration")

ML_SERVER = "http://localhost:8000"
HEXSTRIKE_SERVER = "http://localhost:8001"  # Adjust port if needed

class ChatRequest(BaseModel):
    message: str
    commands: List[str] = []

class ChatResponse(BaseModel):
    analysis_results: List[dict]
    summary: str
    recommendations: List[str]

@app.post("/chat_analyze")
async def chat_analyze(request: ChatRequest):
    """Endpoint for GitHub Copilot chat integration"""
    
    if not request.commands:
        # Extract commands from message if not explicitly provided
        request.commands = extract_commands_from_message(request.message)
    
    # Get ML analysis
    ml_response = requests.post(
        f"{ML_SERVER}/analyze",
        json={"commands": request.commands},
        timeout=10
    )
    ml_results = ml_response.json()
    
    # Generate summary and recommendations
    summary, recommendations = generate_summary(ml_results)
    
    return ChatResponse(
        analysis_results=ml_results,
        summary=summary,
        recommendations=recommendations
    )

def extract_commands_from_message(message: str) -> List[str]:
    """Extract potential commands from conversational message"""
    import re
    # Simple extraction - look for lines that might be commands
    lines = message.split('\n')
    commands = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith(('#', '//', '/*')):
            # Check if it looks like a command
            if any(x in line for x in ['sudo', 'rm', 'cat', 'ls', 'chmod', 'curl', 'wget', '|', ';', '&&']):
                commands.append(line)
    return commands if commands else [message]

def generate_summary(ml_results: List[dict]) -> tuple:
    """Generate human-readable summary and recommendations"""
    total = len(ml_results)
    malicious_count = sum(1 for r in ml_results if r['is_malicious'])
    
    if malicious_count == 0:
        summary = f"✅ All {total} command(s) appear safe."
        recommendations = ["Commands can be executed with normal precautions"]
    else:
        summary = f"⚠️ {malicious_count} out of {total} command(s) flagged as potentially malicious."
        recommendations = [
            f"🚫 Block execution of {malicious_count} malicious command(s)",
            "Review command sources and validate input",
            "Consider running in sandboxed environment",
            "Alert security team if from untrusted source"
        ]
        
        # Add specific mitigations
        for result in ml_results:
            if result['is_malicious']:
                recommendations.append(
                    f"Command '{result['command'][:50]}...' - Risk factors: {', '.join(result['risk_factors'])}"
                )
    
    return summary, recommendations

@app.get("/")
async def root():
    return {"message": "MCP Bridge for ML Model + HexStrike AI Integration"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
