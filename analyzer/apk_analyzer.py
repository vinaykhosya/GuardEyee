from androguard.misc import AnalyzeAPK
import re
import os
from collections import defaultdict
from analyzer.utils import DEST_DIR
from analyzer.report_generator import store_result

# ⚠️ Dangerous permissions that indicate risk
DANGEROUS_PERMISSIONS = {
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "CALL_PHONE", "READ_CALL_LOG",
    "RECORD_AUDIO", "CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"
}

# ⚠️ Suspicious API patterns for scanning method calls
SUSPICIOUS_API_CALLS = {
    "Network": r"Ljava/net/URL;",
    "Commands": r"Ljava/lang/Runtime;->exec",
    "SMS": r"Landroid/telephony/SmsManager;"
}

def analyze_apk_file(apk_path, log):
    basename = os.path.basename(apk_path)
    print(f"\n📱 Scanning APK: {basename}", file=log)

    score = 0
    verdict = "❌ Error"

    try:
        a, d, dx = AnalyzeAPK(apk_path)
        perms = a.get_permissions()

        # 🔍 Check dangerous permissions
        dangerous_perms = [p for p in perms if any(p.endswith(dp) for dp in DANGEROUS_PERMISSIONS)]
        if dangerous_perms:
            print("⚠️ Dangerous permissions found:", file=log)
            for p in dangerous_perms:
                print(f" - {p}", file=log)
            score += len(dangerous_perms) * 2
        else:
            print("✅ No dangerous permissions", file=log)

        # 🔍 Suspicious API call detection
        findings = defaultdict(list)
        for method in dx.get_methods():
            if method.is_external():
                continue
            for _, called, _ in method.get_xref_to():
                m_str = f"{called.class_name}->{called.name}"
                for cat, pat in SUSPICIOUS_API_CALLS.items():
                    if re.search(pat, m_str):
                        findings[cat].append(m_str)

        if findings:
            print("⚠️ Suspicious API usage:", file=log)
            for cat, lst in findings.items():
                print(f" - {cat}: {len(lst)} calls", file=log)
                score += len(lst)
        else:
            print("✅ No suspicious API calls found", file=log)

        # 🧠 Risk verdict
        if score == 0:
            verdict = "🟢 Clean"
            print(f"✅ Verdict: Clean APK ✅", file=log)
        elif score < 10:
            verdict = "🟡 Low Risk"
            print(f"🟡 Verdict: Mildly suspicious (Score: {score})", file=log)
        else:
            verdict = "🔴 High Risk"
            print(f"🔴 Verdict: High-risk APK! (Score: {score})", file=log)

    except Exception as e:
        print(f"❌ Error analyzing {basename}: {e}", file=log)
        verdict = "❌ Error"

    # 📝 Store result
    store_result("APKs", {
        "filename": basename,
        "score": score,
        "risk_level": verdict,
        "path": apk_path
    })

    print("-" * 50, file=log)


def analyze_all_apks(log):
    apk_dir = os.path.join(DEST_DIR, "APKs")
    if not os.path.exists(apk_dir):
        print("📂 APK directory not found.", file=log)
        return

    apk_files = [os.path.join(apk_dir, f) for f in os.listdir(apk_dir) if f.endswith(".apk")]
    if not apk_files:
        print("📁 No APK files found to scan.", file=log)
        return

    print("\n🧪 Starting APK Analysis...\n", file=log)

    for apk in apk_files:
        analyze_apk_file(apk, log)

    print("\n✅ Finished scanning all APKs.\n", file=log)
