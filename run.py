import os
import sys
import subprocess

MAIN_FILE = "main.py"   # 👈 change to your file name

# if not inside venv
if sys.prefix == sys.base_prefix:
    print("🔄 Activating virtual environment...")

    activate_script = os.path.join("venv", "Scripts", "activate.bat")

    if os.path.exists(activate_script):
        subprocess.call(
            f'cmd /k "{activate_script} && python {MAIN_FILE}"',
            shell=True
        )
    else:
        print("❌ venv not found. Run once: python -m venv venv")

else:
    # already inside venv → just run file normally
    subprocess.call(f"python {MAIN_FILE}", shell=True)
