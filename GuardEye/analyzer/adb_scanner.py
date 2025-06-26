import os
import subprocess

def full_safe_pull_via_cmd(log=None):
    print("📡 Attempting full pull using `adb pull /sdcard`...", file=log or None)
    target_dir = os.path.abspath("PulledFiles/Raw")

    # Ensure target directory exists
    os.makedirs(target_dir, exist_ok=True)

    # Run adb pull using raw command (not subprocess.run for safety)
    try:
        result = subprocess.run(
            ["adb", "pull", "/sdcard", target_dir],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("✅ ADB full pull completed successfully.", file=log or None)
        else:
            print("⚠️ ADB pull finished with errors. Some files may be skipped.", file=log or None)
            print(result.stderr, file=log or None)

    except Exception as e:
        print(f"❌ ADB pull failed: {e}", file=log or None)
        raise e
