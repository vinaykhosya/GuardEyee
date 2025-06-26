import os
import subprocess
import re
from analyzer.utils import DEST_DIR
from analyzer.report_generator import store_result  # ✅ Added to log reports

# Adjusted suspicious tag weights
HIGH_RISK_TAGS = {"/launch": 5}
MEDIUM_RISK_TAGS = {"/embeddedfile": 3, "/richmedia": 3, "/javascript": 2, "/js": 2}
LOW_RISK_TAGS = {"/openaction": 1, "/aa": 1, "/acroform": 1}
ALL_TAGS = {**HIGH_RISK_TAGS, **MEDIUM_RISK_TAGS, **LOW_RISK_TAGS}

# Patterns that signal malicious JS
SUSPICIOUS_JS_PATTERNS = [r"eval\\(", r"this\\.exportDataObject", r"app\\.launchURL"]

def analyze_all_pdfs(log=None):
    folder = os.path.join(DEST_DIR, "Documents")
    if not os.path.exists(folder):
        print("📁 PDF folder not found.", file=log or None)
        return

    for filename in os.listdir(folder):
        if filename.lower().endswith(".pdf"):
            pdf_path = os.path.join(folder, filename)
            analyze_pdf(pdf_path, log=log)

def analyze_pdf(pdf_path, log=None):
    def log_print(msg):
        print(msg, file=log or None)

    if not os.path.exists(pdf_path):
        msg = f"❌ File not found: {pdf_path}"
        log_print(msg)
        store_result("Documents", {
            "filename": os.path.basename(pdf_path),
            "score": 0,
            "risk_level": "error",
            "path": pdf_path
        })
        return

    basename = os.path.basename(pdf_path)
    log_print(f"\n📄 Analyzing PDF: {basename}")

    score = 0
    results = []
    tags_found = []
    high_risk_tags_found = False

    # ➤ Structural Tag Scan
    try:
        result = subprocess.run(["python", "tools/pdfid.py", pdf_path],
                                capture_output=True, text=True, check=True)
        output = result.stdout.lower()

        results.append("🔍 Structural Tag Analysis:")
        for tag, weight in ALL_TAGS.items():
            if tag in output:
                score += weight
                tags_found.append((tag, weight))
                results.append(f" - {tag} → +{weight} points")
                if tag in HIGH_RISK_TAGS:
                    high_risk_tags_found = True
        if not tags_found:
            results.append("✅ No suspicious structural tags found.")
    except Exception as e:
        results.append(f"[ERROR] Failed to scan PDF structure: {e}")

    # ➤ JavaScript Check with pattern matching
    try:
        results.append("\n🧠 Embedded JavaScript Check:")
        js_result = subprocess.run(["python", "tools/pdf-parser.py", pdf_path, "--search", "/JavaScript"],
                                   capture_output=True, text=True, check=True)
        js_output = js_result.stdout.strip()

        if js_output:
            dangerous_match = any(re.search(p, js_output) for p in SUSPICIOUS_JS_PATTERNS)
            js_score = 5 if dangerous_match else 1
            score += js_score
            results.append(f"⚠️ JavaScript found → +{js_score} points ({'Dangerous' if dangerous_match else 'Benign-like'})")
        else:
            results.append("✅ No embedded JavaScript found.")
    except Exception as e:
        results.append(f"[ERROR] JS check failed: {e}")

    # ➤ Final Risk Assessment (smarter)
    if score == 0:
        risk = "🟢 Clean"
    elif score <= 15:
        risk = "🟡 Low Risk"
    elif score <= 30:
        risk = "🟠 Moderate Risk"
    elif score > 40 and not high_risk_tags_found:
        risk = "🟠 Moderate Risk"
    else:
        risk = "🔴 High Risk"

    results.append(f"\n🧮 Total Risk Score: {score}")
    results.append(f"🔐 Risk Verdict: {risk}")
    results.append("-" * 60)

    summary = "\n".join(results)
    log_print(summary)

    store_result("PDFs", {
        "filename": basename,
        "score": score,
        "risk_level": risk,
        "path": pdf_path,
        "summary": summary
    })


    return {
        "filename": basename,
        "summary": summary,
        "score": score,
        "risk_level": risk
    }
