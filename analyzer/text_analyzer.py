import os
from analyzer.utils import text_malicious_keywords, DEST_DIR
from analyzer.report_generator import store_result  # ✅ Import added

# Weighted keyword mapping (customize based on severity)
KEYWORD_WEIGHTS = {
    "rm -rf": 5, "reverse_shell": 5, "bind_shell": 5, "trojan": 5, "keylogger": 5, "cryptolocker": 5,
    "payload": 4, "exploit": 4, "backdoor": 4, "obfuscate": 4, "injection": 4, "phishing": 4,
    "os.system": 3, "subprocess.call": 3, "system": 3, "exec": 3, "eval": 3, "shell_exec": 3,
    "netcat": 2, "nc": 2, "wget": 2, "curl": 2, "base64_decode": 2, "xor": 2, "ROT13": 2,
    "sqlmap": 2, "csrf": 2, "xss": 2,
    "chmod +x": 1, "mkfifo": 1, "hashlib": 1, "md5": 1, "sha1": 1
}

def scan_text_file(path, log):
    score = 0
    filename = os.path.basename(path)
    print(f"\n📄 Scanning Text File: {filename}", file=log)

    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read().lower()

        matched = []
        for keyword in text_malicious_keywords:
            if keyword in content:
                weight = KEYWORD_WEIGHTS.get(keyword, 1)
                score += weight
                matched.append((keyword, weight))

        if matched:
            print("⚠️ Suspicious keywords found:", file=log)
            for kw, wt in matched:
                print(f" - {kw} → +{wt} points", file=log)
        else:
            print("✅ No suspicious keywords found.", file=log)

    except Exception as e:
        print(f"[!] Error reading file: {e}", file=log)
        store_result("TextFiles", {
            "filename": filename,
            "score": 0,
            "risk_level": "error",
            "path": path
        })
        return

    # Final risk label
    if score == 0:
        verdict = "🟢 Clean"
    elif score <= 5:
        verdict = "🟡 Low Risk"
    elif score <= 10:
        verdict = "🟠 Moderate Risk"
    else:
        verdict = "🔴 High Risk"

    print(f"\n🧮 Final Risk Score: {score}", file=log)
    print(f"🔐 Verdict: {verdict}", file=log)
    print("-" * 50, file=log)

    # ✅ Store result
    store_result("Texts", {
        "filename": filename,
        "score": score,
        "risk_level": verdict,
        "path": path,
        "summary": f"Verdict: {verdict}\nScore: {score}"
    })


def analyze_all_texts(log):
    folder = os.path.join(DEST_DIR, "TextFiles")
    if not os.path.exists(folder):
        print("📁 Text folder not found.", file=log)
        return

    print("\n🧪 Starting Text File Analysis...\n", file=log)
    for f in os.listdir(folder):
        scan_text_file(os.path.join(folder, f), log)
    print("✅ Text analysis complete.\n", file=log)
