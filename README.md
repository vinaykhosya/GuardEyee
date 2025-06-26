# 🛡️ GuardEye: Advanced AI-Driven Malware Detection Suite

> A complete malware analysis and threat detection platform using Artificial Intelligence, reverse engineering, OCR, and embedded file scanning — with optional ESP32 hardware integration.

---

## 🚀 Overview

GuardEye is an **all-in-one malware GuardEye* designed to **empower even non-technical users** to analyze Android devices and files. It combines AI-based techniques with ADB-based file extraction, allowing you to:

- Pull files from connected Android devices.
- Categorize and scan PDFs, APKs, text files, and images.
- Identify hidden malicious payloads, JavaScript, keywords, EXIF data, and suspicious permissions.
- Use ESP32 hardware button as a scanning trigger.

---

## 🔍 Features

✅ **APK Analyzer** – Permission GuardEye API tracer (Androguard)  
✅ **PDF GuardEye* – `pdfid`, `pdf-parser` for JavaScript and embedded threats  
✅ **Text GuardEye* – AI-weighted keyword detector for malware signatures  
✅ **Image GuardEye* – OCR + EXIF metadata scan  
✅ **ESP32 Hardware Support** – Push-button scanning (optional IoT setup)  
✅ **Flask UI** – Minimalistic UI for scan triggers and results  
✅ **Real-time Logging** – `scan_log.txt` generation for transparency

---

## 🧠 How It Works

![Workflow](./static/workflow.png)

1. User connects Android device via ADB.
2. Files are pulled and sorted into types.
3. Each analyzer runs independently:
   - APKs: Permissions + API calls
   - PDFs: Structure & JS detection
   - Text: Malware keywords
   - Images: OCR + metadata
4. Results are aggregated and shown in UI.

---

## 📸 Screenshots

![Home](./static/screenshot1.png)
![Scan Progress](./static/screenshot2.png)
![Scan Report](./static/screenshot3.png)

---

## ⚙️ Installation

```bash
git clone https://github.com/yourusername/GuardEye.git
cd GuardEye
pip install -r requirements.txt
python app.py
=======
# GuardEyee
>>>>>>> d0ae4ec28994163d996ea325904c0668c505e034
