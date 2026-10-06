import os
import time
from ransomguard import config


def fake_encrypt(path):
    with open(path, "rb") as f:
        _ = f.read()
    with open(path, "wb") as f:
        f.write(os.urandom(4096))

    new_path = path + ".locked"
    if os.path.exists(new_path):
        try:
            os.remove(new_path)
        except Exception:
            pass
    os.rename(path, new_path)
    return new_path


def main():
    folder = config.PROTECTED_FOLDER
    print(f"[Simulator] Attacking: {folder}")

    files = [
        os.path.join(folder, f) for f in os.listdir(folder)
        if os.path.isfile(os.path.join(folder, f))
    ]
    files = [f for f in files if not f.endswith(".locked")]

    print(f"[Simulator] Found {len(files)} files. Encrypting...")

    for f in files:
        try:
            os.chmod(f, 0o644)
            new = fake_encrypt(f)
            print(f"[Simulator] Encrypted: {os.path.basename(new)}")
            time.sleep(0.1)
        except Exception as e:
            print(f"[Simulator] Skipped {f}: {e}")


if __name__ == "__main__":
    main()