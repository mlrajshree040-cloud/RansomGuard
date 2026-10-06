import os
import random
import string
from ransomguard import config


DECOY_CONTENT_TEMPLATES = {
    ".docx": "CONFIDENTIAL — Executive Compensation 2026\n{}",
    ".xlsx": "Salary,Bonus,SSN\n{},{},{}\n",
    ".txt":  "Password backup — do not share\n{}",
    ".dat":  "-----BEGIN WALLET KEY-----\n{}\n-----END WALLET KEY-----",
    ".pem":  "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
}


def _random_blob(length=200):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def _fake_content(filename):
    ext = os.path.splitext(filename)[1].lower()
    template = DECOY_CONTENT_TEMPLATES.get(ext, "{}\n")
    return template.format(_random_blob(), _random_blob(9), _random_blob(11))


class DecoyManager:
    def __init__(self, folder):
        self.folder = folder
        self.decoy_paths = []

    def deploy(self):
        os.makedirs(self.folder, exist_ok=True)
        for name in config.DECOY_FILES:
            path = os.path.join(self.folder, name)
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(_fake_content(name))
                try:
                    os.chmod(path, 0o444)
                except Exception:
                    pass
            self.decoy_paths.append(path)
        print(f"[DecoyManager] Deployed {len(self.decoy_paths)} decoy files.")
        return self.decoy_paths

    def is_decoy(self, path):
        return os.path.abspath(path) in {os.path.abspath(p) for p in self.decoy_paths}

    def restore(self):
        for path in self.decoy_paths:
            try:
                if os.path.exists(path):
                    os.chmod(path, 0o644)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(_fake_content(os.path.basename(path)))
                os.chmod(path, 0o444)
            except Exception as e:
                print(f"[DecoyManager] Restore failed for {path}: {e}")