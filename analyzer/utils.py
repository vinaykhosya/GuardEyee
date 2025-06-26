import os
import re
import subprocess
import time
from collections import defaultdict

# Set absolute path for PulledFiles directory
DEST_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "PulledFiles"))

CATEGORIES = {
    "APKs": [".apk"],
    "TextFiles": [".txt", ".log", ".csv", ".xml", ".json"],
    "Images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"],
    "Documents": [".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt"],
    "SystemApps": [],
    "Others": []
}

text_malicious_keywords = [
    "exec", "eval", "base64_decode", "system", "popen", "shell_exec",
    "os.system", "subprocess.call", "wget", "curl", "rm -rf", "chmod +x",
    "mkfifo", "netcat", "nc", "reverse_shell", "bind_shell", "cryptolocker",
    "malware", "trojan", "ransomware", "keylogger", "phishing", "obfuscate",
    "xor", "ROT13", "steganography", "payload", "backdoor", "exploit",
    "injection", "sqlmap", "csrf", "xss", "hashlib", "md5", "sha1"
]

def run_adb_command(command):
    result = subprocess.run(["adb"] + command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout.strip()

def categorize_file(filename):
    ext = filename.lower().split('.')[-1]
    if ext == "apk":
        return "APKs"
    elif ext in ["jpg", "jpeg", "png"]:
        return "Images"
    elif ext in ["txt", "log", "csv"]:
        return "TextFiles"
    elif ext == "pdf":
        return "Documents"
    else:
        return "Unknown"


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
