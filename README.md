## 🚀 Environment Setup

### **Step 1: Clone Repository**

**Linux/macOS:**
```bash
# Navigate to desired directory
cd ~/projects

# Clone the repository
git clone https://github.com/vineethkumar1207/os-command-injection.git
cd os-command-injection
```

**Windows:**
```powershell
# Navigate to desired directory
cd C:\Users\YourName\projects

# Clone the repository
git clone https://github.com/vineethkumar1207/os-command-injection.git
cd os-command-injection
```

---

### **Step 2: Create Virtual Environment**

**Linux/macOS:**
```bash
# Create virtual environment
python3 -m venv venv

# OR specify Python 3.10
python3.10 -m venv venv
```

**Windows:**
```powershell
# Create virtual environment
python -m venv venv

# OR specify Python 3.10 if available
py -3.10 -m venv venv
```

---

### **Step 3: Activate Virtual Environment**

**Linux/macOS:**
```bash
# Activate virtual environment
source venv/bin/activate

# Verify activation (your prompt should show: (venv) $)
```

**Windows:**
```powershell
# PowerShell activation
venv\Scripts\Activate.ps1

# If execution policy error:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
venv\Scripts\Activate.ps1

# Alternative: Command Prompt activation
venv\Scripts\activate.bat

# Verify activation (your prompt should show: (venv))
```

---

### **Step 4: Install Dependencies**

**Linux/macOS:**
```bash
# Upgrade pip, setuptools, wheel
pip install --upgrade pip setuptools wheel

# Install required packages from requirements.txt
pip install -r requirements.txt

# Expected output:
# Successfully installed fastapi==0.104.1 uvicorn==0.24.0 scikit-learn==1.3.0 ...
```

**Windows:**
```powershell
# Upgrade pip, setuptools, wheel
python -m pip install --upgrade pip setuptools wheel

# Install required packages from requirements.txt
pip install -r requirements.txt

# Expected output:
# Successfully installed fastapi==0.104.1 uvicorn==0.24.0 scikit-learn==1.3.0 ...
```

---

## ⚙️ Running the System

### **2.1 Starting All Services**

#### **Automated Startup (Recommended)**

**Linux/macOS:**
```bash
# Make startup script executable
chmod +x start_all.sh

# Run startup script
./start_all.sh

# Expected output:
# Starting ML Command Detection System...
# Starting ML Server on port 8000...
# ML Server PID: 12345
# Starting MCP Bridge on port 8002...
# MCP Bridge PID: 12346
# All services started!
# ML Server: http://127.0.0.1:8000
# MCP Bridge: http://127.0.0.1:8002
```

**Windows:**
```powershell
# Run startup batch file
.\start_all.bat

# Expected output:
# Starting ML Command Detection System...
# Starting ML Server on port 8000...
# Starting MCP Bridge on port 8002...
# All services started!
# ML Server: http://127.0.0.1:8000
# MCP Bridge: http://127.0.0.1:8002
```

---

#### **Manual Startup (if needed)**

**Linux/macOS:**
```bash
# Terminal 1: Start ML Backend Server
cd ~/os-command-injection
source venv/bin/activate
python3 ml_server_pipeline.py

# Terminal 2: Start MCP Bridge Server
cd ~/os-command-injection
source venv/bin/activate
python3 mcp_bridge_stdio.py

# Terminal 3: Start MCP HTTP Bridge (optional)
cd ~/os-command-injection
source venv/bin/activate
python3 mcp_bridge.py
```

**Windows:**
```powershell
# Terminal 1: Start ML Backend Server
cd C:\Users\YourName\os-command-injection
venv\Scripts\Activate.ps1
python ml_server_pipeline.py

# Terminal 2: Start MCP Bridge Server
cd C:\Users\YourName\os-command-injection
venv\Scripts\Activate.ps1
python mcp_bridge_stdio.py

# Terminal 3: Start MCP HTTP Bridge (optional)
cd C:\Users\YourName\os-command-injection
venv\Scripts\Activate.ps1
python mcp_bridge.py
```

---

## 🔧 Configuring VS Code MCP

### **Step 1: Create MCP Configuration File**

**Linux/macOS:**
```bash
# Create .config directory if needed
mkdir -p ~/.config/Code/User

# Create or edit mcp.json
nano ~/.config/Code/User/mcp.json

# OR use VS Code
code ~/.config/Code/User/mcp.json
```

**Windows:**
```powershell
# Create directory if needed
New-Item -ItemType Directory -Path "$env:APPDATA\Code\User" -Force

# Create or edit mcp.json
notepad "$env:APPDATA\Code\User\mcp.json"

# OR use VS Code
code "$env:APPDATA\Code\User\mcp.json"
```

---

### **Step 2: Add Configuration**

**Linux/macOS:**
```json
{
  "ml-command-detector": {
    "type": "stdio",
    "command": "/home/user/os-command-injection/venv/bin/python",
    "args": ["/home/user/os-command-injection/mcp_bridge_stdio.py"],
    "env": {
      "ML_SERVER": "http://127.0.0.1:8000"
    }
  }
}
```

**Windows:**
```json
{
  "ml-command-detector": {
    "type": "stdio",
    "command": "C:\\Users\\YourName\\os-command-injection\\venv\\Scripts\\python.exe",
    "args": ["C:\\Users\\YourName\\os-command-injection\\mcp_bridge_stdio.py"],
    "env": {
      "ML_SERVER": "http://127.0.0.1:8000"
    }
  }
}
```

**Important:** Replace `/home/user/` or `C:\\Users\\YourName\\` with your actual project path!

---

### **Step 3: Restart VS Code**

**Linux/macOS:**
```bash
# Close VS Code completely
killall code

# Reopen VS Code
code

# Wait 5-10 seconds for MCP server to register
# The ml-command-detector server should now appear in MCP Panel
```

**Windows:**
```powershell
# Close VS Code completely
Stop-Process -Name "Code" -Force

# Reopen VS Code
code

# Wait 5-10 seconds for MCP server to register
# The ml-command-detector server should now appear in MCP Panel
```

---

## ✅ Quick Start

**Linux/macOS:**
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start services
./start_all.sh

# 3. Verify health
curl http://127.0.0.1:8000/health

# 4. Configure VS Code
# Add mcp.json to ~/.config/Code/User/

# 5. Restart VS Code and use in GitHub Copilot Chat
```

**Windows:**
```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start services
.\start_all.bat

# 3. Verify health
curl http://127.0.0.1:8000/health
# OR
Invoke-WebRequest -Uri http://127.0.0.1:8000/health

# 4. Configure VS Code
# Add mcp.json to %APPDATA%\Code\User\

# 5. Restart VS Code and use in GitHub Copilot Chat
```

---

### **Requirements File Contents (`requirements.txt`)**

```txt
fastapi==0.104.1
uvicorn==0.24.0
scikit-learn==1.3.0
pandas==2.0.3
numpy==1.24.3
joblib==1.3.2
requests==2.31.0
pydantic==2.4.2
```

---

##  Troubleshooting and Maintenance

### 5.1 Common Issues and Solutions

#### **Issue 1: "Connection refused" on port 8000**

**Linux/macOS:**
```bash
# Check if ML server is running
ps aux | grep ml_server_pipeline.py

# If not running, start manually:
python3 ml_server_pipeline.py

# Check for port conflicts:
lsof -i :8000

# If port in use, kill existing process:
kill -9 <PID>
```

**Windows:**
```powershell
# Check if ML server is running
Get-Process python | Where-Object {$_.Path -like "*ml_server_pipeline*"}

# If not running, start manually:
python ml_server_pipeline.py

# Check for port conflicts:
netstat -ano | findstr :8000

# If port in use, kill existing process:
taskkill /PID <PID> /F
```

---

#### **Issue 2: "Model not found" error**

**Linux/macOS:**
```bash
# Verify model file exists:
ls -lh models/os_cmd_injection_pipeline.joblib

# If missing, regenerate or restore from backup:
python3 generate_training_dataset.py
python3 train_model.py

# Check model file permissions:
chmod 644 models/os_cmd_injection_pipeline.joblib
```

**Windows:**
```powershell
# Verify model file exists:
Get-Item models\os_cmd_injection_pipeline.joblib | Select-Object Name, Length, LastWriteTime

# If missing, regenerate:
python generate_training_dataset.py
python train_model.py

# Check if file is accessible:
Test-Path models\os_cmd_injection_pipeline.joblib
```

---

#### **Issue 3: "MCP server not appearing in VS Code"**

**Linux/macOS:**
```bash
# Verify mcp.json configuration:
cat ~/.config/Code/User/mcp.json

# Check paths are correct:
ls -la /home/user/os-command-injection-ml/venv/bin/python

# Restart VS Code completely:
killall code
code

# View MCP debug logs:
tail -f ~/.config/Code/User/mcp_debug.log
```

**Windows:**
```powershell
# Verify mcp.json configuration:
Get-Content $env:APPDATA\Code\User\mcp.json

# Check paths are correct:
Test-Path C:\Users\YourName\os-command-injection-ml\venv\Scripts\python.exe

# Restart VS Code completely:
Stop-Process -Name "Code" -Force
Start-Process code

# View MCP debug logs (if available):
Get-Content $env:APPDATA\Code\User\mcp_debug.log -Tail 50
```

---

#### **Issue 4: Virtual environment activation fails**

**Linux/macOS:**
```bash
# Recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows:**
```powershell
# Recreate virtual environment
Remove-Item -Recurse -Force venv
python -m venv venv
venv\Scripts\Activate.ps1

# If execution policy error:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
venv\Scripts\Activate.ps1

# Alternative activation:
venv\Scripts\activate.bat

# Install dependencies:
pip install -r requirements.txt
```

---

#### **Issue 5: "Permission denied" or "Access denied"**

**Linux/macOS:**
```bash
# Fix script permissions:
chmod +x start_all.sh stop_all.sh

# Fix file ownership:
sudo chown -R $USER:$USER ~/os-command-injection-ml
```

**Windows:**
```powershell
# Run as Administrator:
# Right-click PowerShell -> Run as Administrator

# Check if file is read-only:
Get-ItemProperty models\os_cmd_injection_pipeline.joblib | Select-Object IsReadOnly

# Remove read-only attribute:
Set-ItemProperty models\os_cmd_injection_pipeline.joblib -Name IsReadOnly -Value $false
```

---

### 6.2 Performance Monitoring

**Linux/macOS:**
```bash
# Monitor real-time resource usage:
watch -n 1 'ps aux | grep python | grep -v grep'

# View memory consumption:
ps -o pid,vsz,rss,comm | grep ml_server

# Monitor disk space:
du -sh ~/os-command-injection-ml
```

**Windows:**
```powershell
# Monitor real-time resource usage:
while ($true) { 
  Get-Process python | Select-Object Id, CPU, WorkingSet, ProcessName
  Start-Sleep -Seconds 1
  Clear-Host
}

# View memory consumption:
Get-Process python | Select-Object Id, @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet / 1MB, 2)}}, ProcessName

# Monitor disk space:
Get-ChildItem -Recurse | Measure-Object -Property Length -Sum | Select-Object @{Name="Size(MB)";Expression={[math]::Round($_.Sum / 1MB, 2)}}
```

---

### 6.3 Logs Location

**Linux/macOS:**
- ML Server logs: `./ml_server.log`
- MCP Bridge logs: `./mcp_bridge.log`
- System logs: `/var/log/syslog`

**Windows:**
- ML Server logs: `.\ml_server.log`
- MCP Bridge logs: `.\mcp_bridge.log`
- View logs: `Get-Content .\ml_server.log -Tail 50 -Wait`

---

### 6.4 Quick Diagnostics

```bash
# Linux/macOS: Run comprehensive check
python3 test_mcp.py

# Windows: Run comprehensive check
python test_mcp.py
```

**Expected output:**
```
✓ ML Backend Health: HEALTHY
✓ MCP Bridge Status: OPERATIONAL
✓ Benign Command Test: PASSED
✓ Malicious Command Test: PASSED
✓ Batch Analysis Test: PASSED
All tests completed successfully!
```

---

## 📞 Support

If you encounter issues not covered here:

1. Check [GitHub Issues](https://github.com/vineethkumar1207/os-command-injection/issues)
2. Review configuration manual: `docs/23411538_MSc-Reseach-Practicum-Part-2-Config-manual.docx`
3. Verify all prerequisites are installed
4. Check system requirements (Python 3.10+, 4GB RAM)

---

## 👨‍🎓 Author

**Vineeth Kumar Dodda**  

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

Based on research from:
- Yuan et al. (2020) - TF-IDF for security detection
- Wang et al. (2024) - CNN-BiLSTM-Attention for command injection
- Ye et al. (2024) - LLM-based taint analysis
- OWASP Top 10 - 2021




