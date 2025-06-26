import os
import sys
import shutil
from analyzer.utils import DEST_DIR
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from analyzer.utils import categorize_file

EXT_MAP = {
    "apk": "APKs",
    "txt": "TextFiles",
    "log": "TextFiles",
    "csv": "TextFiles",
    "json": "TextFiles",
    "pdf": "Documents",
    "jpg": "Images",
    "jpeg": "Images",
    "png": "Images",
    "bmp": "Images",
    "gif": "Images",
    "webp": "Images",
}

def sort_files(log=None):
    raw_dir = os.path.join(DEST_DIR, "Raw")
    if not os.path.exists(raw_dir):
        print("❌ Raw folder not found. Cannot sort files.", file=log or None)
        return

    print("📦 Sorting pulled files into categories...\n", file=log or None)

    for root, _, files in os.walk(raw_dir):
        for file in files:
            src_path = os.path.join(root, file)
            category = categorize_file(file)
            dest_dir = os.path.join(DEST_DIR, category)
            os.makedirs(dest_dir, exist_ok=True)

            dest_path = os.path.join(dest_dir, file)
            try:
                shutil.move(src_path, dest_path)
                print(f"✅ Moved: {file} → {category}", file=log or None)
            except Exception as e:
                print(f"❌ Failed to move {file}: {e}", file=log or None)
