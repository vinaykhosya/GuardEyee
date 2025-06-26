from flask import Flask, request, render_template, redirect, url_for, jsonify
import os
import subprocess
import time
import threading
from analyzer.sorter import sort_files
from analyzer import apk_analyzer, text_analyzer, image_analyzer, pdf_analyzer
from analyzer.report_generator import reset_report, get_final_report

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
scan_summary = ""

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/upload")
def upload_page():
    return render_template("upload.html")

@app.route("/check-adb-device")
def check_adb_device():
    try:
        result = subprocess.check_output(["adb", "devices"], encoding="utf-8")
        devices = result.strip().split('\n')[1:]
        if devices and devices[0].strip():
            return render_template("adb_confirm.html", device_connected=True, device_info="\n".join(devices))
        return render_template("adb_confirm.html", device_connected=False, device_info="No device connected.")
    except Exception as e:
        return render_template("adb_confirm.html", device_connected=False, device_info=f"ADB error: {str(e)}")

@app.route("/confirm-device-scan", methods=["POST"])
def confirm_device_scan():
    return redirect("/scanning")

@app.route("/scanning")
def scanning_page():
    return render_template("scanning.html")

@app.route("/run-background-scan", methods=["POST"])
def run_background_scan():
    def scan_task():
        global scan_summary
        with open("scan_log.txt", "w", encoding="utf-8") as log:
            try:
                reset_report()
                log.write("🧠 Starting scan of already pulled files...\n")
                sort_files(log)

                def safe_run(analyzer_func, name):
                    try:
                        analyzer_func(log)
                    except Exception as e:
                        log.write(f"❌ {name} analyzer failed: {str(e)}\n")

                threads = [
                    threading.Thread(target=safe_run, args=(apk_analyzer.analyze_all_apks, "APK")),
                    threading.Thread(target=safe_run, args=(text_analyzer.analyze_all_texts, "Text")),
                    threading.Thread(target=safe_run, args=(image_analyzer.analyze_all_images, "Image")),
                    threading.Thread(target=safe_run, args=(pdf_analyzer.analyze_all_pdfs, "PDF")),
                ]

                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

                scan_summary = "✅ Scan complete! View detailed results."
                log.write(scan_summary + "\n")
            except Exception as e:
                scan_summary = f"❌ Scan failed: {str(e)}"
                log.write(scan_summary + "\n")

    threading.Thread(target=scan_task).start()
    return "", 204

@app.route("/get-scan-result")
def get_scan_result():
    global scan_summary
    if scan_summary:
        summary = scan_summary
        scan_summary = ""
        return {"ready": True, "summary": summary}
    return {"ready": False}

@app.route("/get-scan-log")
def get_scan_log():
    try:
        with open("scan_log.txt", "r", encoding="utf-8") as f:
            lines = f.readlines()[-7:]
        return {"lines": lines}
    except FileNotFoundError:
        return {"lines": ["[Waiting for scan to start...]"]}

@app.route("/scan-file", methods=["POST"])
def scan_file():
    file = request.files.get("file")
    if not file:
        return "No file received."

    filename = file.filename
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)

    ext = filename.lower().split('.')[-1]
    result, icon, status_class, details = "Unknown", "❔", "danger", "No analyzer matched."

    try:
        if ext == "apk":
            apk_analyzer.analyze_apk_file(save_path, log=None)
            result = "APK analyzed for permissions and dangerous API usage."
            icon, status_class, details = "📱", "danger", "APK analysis complete."
        elif ext == "txt":
            score, verdict = text_analyzer.scan_text_file(save_path, log=None)
            result = "Text file scanned for malicious keywords."
            icon, status_class = "📄", "warning" if score > 5 else "safe"
            details = f"Verdict: {verdict}\nScore: {score}"
        elif ext == "pdf":
            report = pdf_analyzer.analyze_pdf(save_path)
            result = "PDF scanned for structural threats and scripts."
            icon = "📄"
            status_class = "warning" if report["score"] >= 5 else "safe"
            details = f"{report['summary']}\n\n🧮 Final Risk Score: {report['score']} points"
        elif ext in ["png", "jpg", "jpeg"]:
            score, verdict = image_analyzer.analyze_image(save_path, log=None)
            result = "Image scanned for suspicious text via OCR."
            icon, status_class = "🖼️", "warning" if score > 5 else "safe"
            details = f"Verdict: {verdict}\nScore: {score}"
        else:
            result = "Unsupported file type"
            icon, status_class, details = "❌", "danger", "No analyzer available."
    except Exception as e:
        result = f"Scan failed: {str(e)}"
        icon, status_class, details = "⚠️", "danger", "Error occurred during scan."

    return render_template("result.html", filename=filename, result=result,
                           icon=icon, status_class=status_class, details=details)

@app.route("/full-scan-result")
def full_scan_result():
    return render_template("full_scan_result.html", summary=scan_summary, report=get_final_report())

@app.route("/pull-files", methods=["POST"])
def pull_files():
    os.makedirs("PulledFiles\\Raw", exist_ok=True)
    cmd = ["cmd.exe", "/c", "start", "cmd.exe", "/k", "adb pull /sdcard PulledFiles\\Raw"]
    subprocess.Popen(cmd)
    return redirect("/check-adb-device")

@app.route("/start-scan", methods=["POST"])
def start_scan():
    return redirect("/scanning")

if __name__ == "__main__":
    app.run(debug=True)
