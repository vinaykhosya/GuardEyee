import os
from PIL import Image
import pytesseract
import exifread
from analyzer.utils import text_malicious_keywords, DEST_DIR
from analyzer.report_generator import store_result

def analyze_image(img_path, log):
    score = 0
    basename = os.path.basename(img_path)
    print(f"\n🖼️ Scanning Image: {basename}", file=log)

    flags = []

    try:
        # OCR Text Extraction
        with Image.open(img_path) as img:
            text = pytesseract.image_to_string(img).lower()

        # EXIF Metadata Extraction
        with open(img_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)

        # Keyword Matching
        for kw in text_malicious_keywords:
            if kw in text:
                flags.append(f"Text: {kw}")
            elif any(kw in str(tag).lower() for tag in tags.values()):
                flags.append(f"EXIF: {kw}")

        if flags:
            print("⚠️ Suspicious content detected in image:", file=log)
            for f in flags:
                print(f" - {f}", file=log)
            score += len(flags) * 2
        else:
            print("✅ No suspicious keywords or metadata found.", file=log)

    except Exception as e:
        print(f"❌ Error analyzing image: {e}", file=log)

    # Final Verdict
    if score == 0:
        verdict = "🟢 Clean"
    elif score < 6:
        verdict = "🟡 Suspicious"
    else:
        verdict = "🔴 High Risk"

    print(f"✅ Verdict: {verdict} (Score: {score})", file=log)
    print("-" * 50, file=log)

    store_result("Images", {
        "filename": basename,
        "score": score,
        "risk_level": verdict,
        "path": img_path
    })

def analyze_all_images(log):
    folder = os.path.join(DEST_DIR, "Images")
    if not os.path.exists(folder):
        print("📂 Image folder not found.", file=log)
        return

    images = [f for f in os.listdir(folder) if f.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp'))]
    if not images:
        print("📁 No image files to scan.", file=log)
        return

    print("\n🧪 Starting Image Analysis...\n", file=log)
    for img in images:
        analyze_image(os.path.join(folder, img), log)
    print("\n✅ Finished scanning all images.\n", file=log)

def scan_single_image_file(file_path, log=None):
    if os.path.exists(file_path) and file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp')):
        analyze_image(file_path, log)
    else:
        print("❌ Not a valid image file or file does not exist.", file=log)
