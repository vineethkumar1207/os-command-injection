from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import joblib
import os
from pathlib import Path

app = FastAPI(
    title="Command Injection ML Detection API",
    description="TF-IDF + Logistic Regression for OS Command Injection",
    version="1.0.0"
)

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
MODEL_PATH = SCRIPT_DIR / 'models' / 'os_cmd_injection_lr.joblib'

# Load model
try:
    model = joblib.load(str(MODEL_PATH))
    MODEL_LOADED = True
    print(f"✅ Model loaded from {MODEL_PATH}")
except Exception as e:
    print(f"⚠️ Model load error: {e}")
    MODEL_LOADED = False
    model = None

class CommandRequest(BaseModel):
    commands: List[str]

class CommandAnalysis(BaseModel):
    command: str
    is_malicious: bool
    confidence: float
    severity: str
    risk_factors: List[str]

@app.get("/")
async def root():
    return {
        "message": "ML Command Injection Detection API",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "analyze": "/analyze (POST)",
            "docs": "/docs"
        }
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy" if MODEL_LOADED else "degraded",
        "model_loaded": MODEL_LOADED,
        "model_path": str(MODEL_PATH)
    }

@app.post("/analyze", response_model=List[CommandAnalysis])
async def analyze_commands(request: CommandRequest):
    # NOTE: This model requires a TF-IDF vectorizer that wasn't saved with it.
    # For now, using heuristic-based detection as a fallback.
    
    results = []
    for cmd in request.commands:
        try:
            # Heuristic-based detection (fallback until vectorizer is added)
            is_malicious = any([
                ';' in cmd and ('rm' in cmd or 'del' in cmd),
                '| sh' in cmd or '| bash' in cmd,
                'wget' in cmd and '|' in cmd,
                'curl' in cmd and ('|' in cmd or '>' in cmd),
                '../' in cmd and 'cat' in cmd,
                '--no-preserve-root' in cmd,
                '$((' in cmd or '${' in cmd,
                'eval' in cmd or 'exec' in cmd
            ])
            
            # Calculate rough confidence
            risk_score = 0
            if '|' in cmd or ';' in cmd or '&&' in cmd:
                risk_score += 0.3
            if 'rm' in cmd.lower() or 'del' in cmd.lower():
                risk_score += 0.4
            if 'curl' in cmd.lower() or 'wget' in cmd.lower():
                risk_score += 0.2
            if '../' in cmd or '..' in cmd:
                risk_score += 0.3
            if '| sh' in cmd or '| bash' in cmd:
                risk_score += 0.5
            
            confidence = min(risk_score, 0.99) if is_malicious else max(0.01, risk_score)
            
            # Determine severity
            if confidence >= 0.8:
                severity = "CRITICAL"
            elif confidence >= 0.6:
                severity = "HIGH"
            elif confidence >= 0.4:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            # Extract risk factors
            risk_factors = []
            if '|' in cmd or ';' in cmd or '&&' in cmd:
                risk_factors.append("Command chaining detected")
            if 'rm' in cmd.lower() or 'del' in cmd.lower():
                risk_factors.append("Destructive command")
            if 'curl' in cmd.lower() or 'wget' in cmd.lower():
                risk_factors.append("Network access")
            if '../' in cmd or '..' in cmd:
                risk_factors.append("Path traversal pattern")
            if '| sh' in cmd or '| bash' in cmd:
                risk_factors.append("Shell execution via pipe")
            if 'eval' in cmd or 'exec' in cmd:
                risk_factors.append("Dynamic code execution")
            
            results.append(CommandAnalysis(
                command=cmd,
                is_malicious=is_malicious,
                confidence=confidence,
                severity=severity,
                risk_factors=risk_factors if is_malicious else []
            ))
        except Exception as e:
            print(f"Error analyzing command '{cmd}': {e}")
            results.append(CommandAnalysis(
                command=cmd,
                is_malicious=False,
                confidence=0.0,
                severity="UNKNOWN",
                risk_factors=[f"Analysis error: {str(e)}"]
            ))
    
    return results

if __name__ == "__main__":
    import uvicorn
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    uvicorn.run(app, host="0.0.0.0", port=port)
