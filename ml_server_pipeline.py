from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import joblib
import os
from pathlib import Path
import numpy as np

app = FastAPI(
    title="Command Injection ML Detection API",
    description="TF-IDF + Logistic Regression for OS Command Injection",
    version="2.0.0"
)

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
PIPELINE_PATH = SCRIPT_DIR / 'models' / 'os_cmd_injection_pipeline.joblib'

# Load pipeline (TF-IDF + LogisticRegression)
try:
    pipeline = joblib.load(str(PIPELINE_PATH))
    MODEL_LOADED = True
    print(f"✅ Pipeline loaded from {PIPELINE_PATH}")
    print(f"   Model: {type(pipeline.named_steps['clf']).__name__}")
    print(f"   Vectorizer: {type(pipeline.named_steps['tfidf']).__name__}")
except Exception as e:
    print(f"⚠️ Pipeline load error: {e}")
    MODEL_LOADED = False
    pipeline = None

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
        "model_type": "TF-IDF + Logistic Regression Pipeline",
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
        "model_type": "sklearn.Pipeline (TfidfVectorizer + LogisticRegression)" if MODEL_LOADED else "N/A",
        "pipeline_path": str(PIPELINE_PATH)
    }

@app.post("/analyze", response_model=List[CommandAnalysis])
async def analyze_commands(request: CommandRequest):
    if not MODEL_LOADED:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    results = []
    for cmd in request.commands:
        try:
            # Use trained pipeline to predict
            prediction = pipeline.predict([cmd])[0]  # 0 = benign, 1 = malicious
            probabilities = pipeline.predict_proba([cmd])[0]
            
            # Map probability to the index of class=1 explicitly to avoid inversion
            classes = list(pipeline.named_steps['clf'].classes_)
            try:
                idx_mal = classes.index(1)
            except ValueError:
                # Fallback: if label 1 isn't present, assume last class is malicious
                idx_mal = len(classes) - 1

            malicious_prob = float(probabilities[idx_mal])

            # Hybrid: boost probability for critical patterns to avoid reverse detection
            cmd_lower = cmd.lower()
            critical_patterns = [
                '| sh', '| bash', '|| sh', '|| bash',
                '`', '$(', '$((',
                '/dev/tcp', '/dev/udp',
                'nc -e', 'ncat -e', 'bash -i >& /dev/tcp',
                'curl ' in cmd_lower and '|' in cmd,
                'wget ' in cmd_lower and '|' in cmd,
                '%0a' in cmd_lower or '%3b' in cmd_lower or '%7c' in cmd_lower
            ]
            if any([
                ('| sh' in cmd_lower or '| bash' in cmd_lower),
                ('`' in cmd or '$(' in cmd),
                ('/dev/tcp' in cmd_lower or '/dev/udp' in cmd_lower),
                ('nc -e' in cmd_lower or 'ncat -e' in cmd_lower),
                ('curl ' in cmd_lower and '|' in cmd),
                ('wget ' in cmd_lower and '|' in cmd),
                ('%0a' in cmd_lower or '%3b' in cmd_lower or '%7c' in cmd_lower)
            ]):
                malicious_prob = max(malicious_prob, 0.85)

            # Decide maliciousness from probability directly
            is_malicious = malicious_prob >= 0.5
            confidence = malicious_prob

            # Severity mapping requested: 0-35% low, 36-75% medium, 76-100% high
            if confidence >= 0.76:
                severity = "HIGH"
            elif confidence >= 0.36:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            # Extract risk factors based on command patterns
            risk_factors = []
            if is_malicious:
                if '|' in cmd or ';' in cmd or '&&' in cmd or '||' in cmd:
                    risk_factors.append("Command chaining detected")
                if any(char in cmd for char in ['`', '$(']):
                    risk_factors.append("Command substitution")
                if 'rm' in cmd.lower() or 'del' in cmd.lower():
                    risk_factors.append("Destructive command")
                if ('curl' in cmd.lower() or 'wget' in cmd.lower()) and ('|' in cmd or '>' in cmd):
                    risk_factors.append("Network access with redirection")
                if '../' in cmd or '..' in cmd:
                    risk_factors.append("Path traversal pattern")
                if '| sh' in cmd or '| bash' in cmd:
                    risk_factors.append("Shell execution via pipe")
                if 'eval' in cmd or 'exec' in cmd:
                    risk_factors.append("Dynamic code execution")
                if '%0A' in cmd or '%0D' in cmd or '%3B' in cmd or '%7C' in cmd:
                    risk_factors.append("URL-encoded injection characters")
                if '/dev/tcp' in cmd or '/dev/udp' in cmd:
                    risk_factors.append("Network socket access")
                if 'nc ' in cmd.lower() or 'netcat' in cmd.lower():
                    risk_factors.append("Network utility (netcat)")
                
                # Generic fallback if no specific patterns matched
                if not risk_factors:
                    risk_factors.append(f"ML model detected malicious pattern ({malicious_prob:.0%} confidence)")
            
            results.append(CommandAnalysis(
                command=cmd,
                is_malicious=is_malicious,
                confidence=confidence,
                severity=severity,
                risk_factors=risk_factors
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
