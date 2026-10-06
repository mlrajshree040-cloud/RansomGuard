import os
import shutil
import hashlib
import time
from ransomguard import config
from ransomguard.logger import log


class RollbackEngine:
    """
    Multi-folder rollback engine.
    Snapshots ALL protected folders into vault/ with hashes.
    Restores files after an attack.
    """

    def __init__(self, folders=None, vault=None):
        if folders is None:
            folders = config.PROTECTED_FOLDERS
        elif isinstance(folders, str):
            folders = [folders]
        self.folders = folders
        self.vault = vault or config.VAULT_FOLDER
        os.makedirs(self.vault, exist_ok=True)
        self.manifests = {}
        self.manifest = {}

    def _hash(self, path):
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _is_decoy(self, path):
        return os.path.basename(path) in config.DECOY_FILES

    def _vault_dir_for(self, folder):
        name = os.path.basename(os.path.normpath(folder))
        return os.path.join(self.vault, name)

    # ---------- Snapshot ----------
    def snapshot(self):
        total = 0
        for folder in self.folders:
            if not os.path.exists(folder):
                os.makedirs(folder, exist_ok=True)
            vdir = self._vault_dir_for(folder)
            os.makedirs(vdir, exist_ok=True)
            manifest = {}

            for root, _, files in os.walk(folder):
                for name in files:
                    src = os.path.join(root, name)
                    if self._is_decoy(src):
                        continue
                    rel = os.path.relpath(src, folder)
                    dst = os.path.join(vdir, rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    try:
                        shutil.copy2(src, dst)
                        h = self._hash(src)
                        if h:
                            manifest[rel] = h
                            total += 1
                    except Exception as e:
                        log.warning(f"[Rollback] Snapshot failed {src}: {e}")

            self.manifests[folder] = manifest

            manifest_file = os.path.join(vdir, "manifest.txt")
            with open(manifest_file, "w", encoding="utf-8") as f:
                for rel, h in manifest.items():
                    f.write(f"{h}  {rel}\n")

        if self.folders:
            self.manifest = self.manifests.get(self.folders[0], {})

        log.info(f"[Rollback] Snapshot complete: {total} files across "
                 f"{len(self.folders)} folders.")
        return total

    # ---------- Restore ----------
    def restore(self):
        restored, failed, removed = 0, 0, 0

        for folder, manifest in self.manifests.items():
            if not os.path.exists(folder):
                continue
            vdir = self._vault_dir_for(folder)

            # 1. Restore modified/missing
            for rel, original_hash in manifest.items():
                live = os.path.join(folder, rel)
                vault_file = os.path.join(vdir, rel)
                live_hash = self._hash(live) if os.path.exists(live) else None

                if live_hash != original_hash:
                    try:
                        os.makedirs(os.path.dirname(live), exist_ok=True)
                        if os.path.exists(live):
                            os.chmod(live, 0o644)
                        shutil.copy2(vault_file, live)
                        os.chmod(live, 0o644)
                        restored += 1
                        log.info(f"[Rollback] Restored: {rel}")
                    except Exception as e:
                        failed += 1
                        log.warning(f"[Rollback] Restore failed {rel}: {e}")

            # 2. Remove rogue files
            for root, _, files in os.walk(folder):
                for name in files:
                    if name in config.DECOY_FILES:
                        continue
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, folder)
                    if rel not in manifest:
                        try:
                            os.chmod(full, 0o644)
                            os.remove(full)
                            removed += 1
                            log.info(f"[Rollback] Removed rogue: {rel}")
                        except Exception as e:
                            log.warning(f"[Rollback] Could not remove {rel}: {e}")

            # 3. Sweep ransomware extensions
            for root, _, files in os.walk(folder):
                for name in files:
                    ext = os.path.splitext(name)[1].lower()
                    if ext in config.RANSOMWARE_EXTENSIONS:
                        full = os.path.join(root, name)
                        try:
                            os.chmod(full, 0o644)
                            os.remove(full)
                            removed += 1
                            log.info(f"[Rollback] Removed ransomware: {name}")
                        except Exception:
                            pass

        result = {
            "restored": restored,
            "removed_rogue": removed,
            "failed": failed,
            "timestamp": time.strftime("%H:%M:%S"),
        }
        log.warning(f"[Rollback] Result: {result}")
        return result

    # ---------- Current manifest ----------
    def current_manifest(self):
        live = {}
        for folder in self.folders:
            if not os.path.exists(folder):
                continue
            for root, _, files in os.walk(folder):
                for name in files:
                    if self._is_decoy(name):
                        continue
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, folder)
                    key = f"{os.path.basename(folder)}/{rel}"
                    h = self._hash(full)
                    if h:
                        live[key] = h
        return live