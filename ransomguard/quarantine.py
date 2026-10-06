import os
import json
import shutil
import hashlib
import time
from ransomguard import config
from ransomguard.logger import log


class QuarantineManager:
    """
    Isolates detected malware files instead of deleting them.

    - Moves files to quarantine/ folder
    - Renames with .quarantine extension (prevents execution)
    - Stores metadata in quarantine/index.json
    - Supports restore and permanent delete
    """

    def __init__(self, folder=None):
        self.folder = folder or config.QUARANTINE_FOLDER
        os.makedirs(self.folder, exist_ok=True)
        self.index_file = os.path.join(self.folder, "index.json")
        self.index = self._load_index()

    # ---------- Index persistence ----------
    def _load_index(self):
        if os.path.exists(self.index_file):
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_index(self):
        try:
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump(self.index, f, indent=2)
        except Exception as e:
            log.error(f"[Quarantine] Failed to save index: {e}")

    # ---------- Helpers ----------
    def _hash(self, path, max_bytes=2 * 1024 * 1024):
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                h.update(f.read(max_bytes))
            return h.hexdigest()
        except Exception:
            return ""

    def _unique_dest(self, basename):
        base = basename + ".quarantine"
        dest = os.path.join(self.folder, base)
        i = 1
        while os.path.exists(dest):
            dest = os.path.join(self.folder, f"{basename}.{i}.quarantine")
            i += 1
        return dest

    # ---------- Quarantine a file ----------
    def quarantine_file(self, path, reason="detected"):
        if not os.path.exists(path):
            return None

        try:
            original_abs = os.path.abspath(path)
            basename = os.path.basename(path)
            file_hash = self._hash(path)
            size = os.path.getsize(path)

            dest = self._unique_dest(basename)

            try:
                os.chmod(path, 0o644)
            except Exception:
                pass

            shutil.move(path, dest)

            entry = {
                "original_path": original_abs,
                "quarantine_path": os.path.abspath(dest),
                "filename": basename,
                "sha256": file_hash,
                "size": size,
                "reason": reason,
                "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.index[os.path.abspath(dest)] = entry
            self._save_index()

            log.warning(f"[Quarantine] Isolated: {basename} ({reason})")
            return entry

        except Exception as e:
            log.error(f"[Quarantine] Failed to isolate {path}: {e}")
            return None

    # ---------- Restore ----------
    def restore_file(self, quarantine_path):
        entry = self.index.get(os.path.abspath(quarantine_path))
        if not entry:
            log.error(f"[Quarantine] Entry not found: {quarantine_path}")
            return False

        try:
            original = entry["original_path"]
            os.makedirs(os.path.dirname(original), exist_ok=True)

            if os.path.exists(original):
                root, ext = os.path.splitext(original)
                original = f"{root}_restored{ext}"

            shutil.move(quarantine_path, original)
            os.chmod(original, 0o644)

            del self.index[os.path.abspath(quarantine_path)]
            self._save_index()

            log.info(f"[Quarantine] Restored: {original}")
            return True

        except Exception as e:
            log.error(f"[Quarantine] Restore failed: {e}")
            return False

    # ---------- Delete ----------
    def delete_file(self, quarantine_path):
        try:
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)
            self.index.pop(os.path.abspath(quarantine_path), None)
            self._save_index()
            log.info(f"[Quarantine] Deleted: {quarantine_path}")
            return True
        except Exception as e:
            log.error(f"[Quarantine] Delete failed: {e}")
            return False

    def delete_all(self):
        count = 0
        for qpath in list(self.index.keys()):
            if self.delete_file(qpath):
                count += 1
        return count

    # ---------- Info ----------
    def count(self):
        return len(self.index)

    def list_all(self):
        return list(self.index.values())