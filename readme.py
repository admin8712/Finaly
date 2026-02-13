import os
import subprocess
import sys

def install_requirements():
    print("\033[38;5;51m[•] Starting ULTIMATUM Setup...\033[0m")
    
    # 1. Update & Install Java/Python dep
    print("\033[38;5;201m[•] Installing System Packages (Java 17 & Python)...\033[0m")
    try:
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "install", "-y", "openjdk-17-jdk", "python3-pip"], check=True)
    except:
        print("\033[38;5;196m[X] Failed to install system packages. Please run as root/sudo.\033[0m")

    # 2. Buat folder kerja
    if not os.path.exists(".vault_v100"):
        os.makedirs(".vault_v100")
        print("\033[38;5;46m[✓] Workspace directory created.\033[0m")

    # 3. Instruksi Manual untuk File Binary
    print("\n\033[38;5;226m[!] PERINGATAN: Pastikan file berikut ada di folder ini:\033[0m")
    required_files = ["apktool.jar", "uber-apk-signer.jar", "frida-64.so", "frida-32.so"]
    for f in required_files:
        status = "\033[38;5;46m[FOUND]\033[0m" if os.path.exists(f) else "\033[38;5;196m[MISSING]\033[0m"
        print(f"    {status} {f}")

    print("\n\033[38;5;51m[•] Setup Selesai! Jalankan tools dengan: python3 m.py\033[0m")

if __name__ == "__main__":
    install_requirements()
