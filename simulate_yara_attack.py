"""
simulate_yara_attack.py
Simulates ransomware behavior that YARA rules will detect.
Run: python simulate_yara_attack.py
"""
import os
import time
from ransomguard import config


def main():
    folder = config.PROTECTED_FOLDER
    print("[Simulator] Writing ransomware note + encrypted files...")

    # 1. Write a ransom note (YARA detects this)
    note_path = os.path.join(folder, "HOW_TO_DECRYPT.txt")
    with open(note_path, "w", encoding="utf-8") as f:
        f.write(
            "Your files have been encrypted!\n"
            "Send bitcoin to 1A2B3C4D5E6F to recover your files.\n"
            "Contact us on tor browser at example.onion\n"
            "Pay the ransom or lose your documents, photos, databases.\n"
            "Use the decryption key we provide after payment.\n"
        )
    print(f"  Wrote ransom note: {note_path}")
    time.sleep(0.5)

    # 2. Simulate encryption on real files
    targets = ["Resume.pdf", "Project.docx", "Financial.xlsx"]
    for name in targets:
        path = os.path.join(folder, name)
        if os.path.exists(path):
            try:
                os.chmod(path, 0o644)
                with open(path, "wb") as f:
                    f.write(os.urandom(4096))
                new_path = path + ".locked"
                if os.path.exists(new_path):
                    try:
                        os.remove(new_path)
                    except Exception:
                        pass
                os.rename(path, new_path)
                print(f"  Encrypted: {os.path.basename(new_path)}")
                time.sleep(0.2)
            except Exception as e:
                print(f"  Skipped {path}: {e}")

    # 3. Write a script with commands YARA detects
    shadow_cmd_file = os.path.join(folder, "cleanup.bat")
    with open(shadow_cmd_file, "w", encoding="utf-8") as f:
        f.write("vssadmin delete shadows /all /quiet\n")
        f.write("bcdedit /set {default} recoveryenabled no\n")
    print(f"  Wrote shadow-copy deletion script: {shadow_cmd_file}")


if __name__ == "__main__":
    main()