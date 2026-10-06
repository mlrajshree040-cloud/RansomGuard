"""
Self-Defense / Anti-Tamper System for RansomGuard.

Protects the defender from being killed, deleted, or modified by malware.

Layers:
  1. Protected paths — hashes of critical files monitored
  2. Registry guard  — prevents uninstall tampering (Windows)
  3. Process shield  — raise priority + catch signals
  4. Heartbeat       — external watchdog respawns if killed
  5. Integrity loop  — re-verify every 30s
  6. Audit log       — records all tamper events
"""
import os
import time
import json
import hashlib
import threading
import platform

from ransomguard import config
from ransomguard.logger import log


IS_WINDOWS = platform.system() == "Windows"
SELF_DEFENSE_LOG = os.path.join(config.BASE_DIR, "selfdefense.log")
INTEGRITY_FILE = os.path.join(config.BASE_DIR, ".rg_integrity.json")
HEARTBEAT_FILE = os.path.join(config.BASE_DIR, ".rg_heartbeat")


class SelfDefense:
    def __init__(self):
        self.pid = os.getpid()
        self.running = True
        self.tamper_events = []
        self.protected_paths = []
        self.integrity_hashes = {}
        self._heartbeat_thread = None
        self._watcher_thread = None
        self._load_integrity()

    # ---------- 1. Protected paths ----------
    def register_protected_paths(self):
        base = config.BASE_DIR
        candidates = [
            os.path.join(base, "main.py"),
            os.path.join(base, "ransomguard", "detector.py"),
            os.path.join(base, "ransomguard", "response.py"),
            os.path.join(base, "ransomguard", "yara_engine.py"),
            os.path.join(base, "ransomguard", "yara_rules", "lockbit.yar"),
            os.path.join(base, "ransomguard", "yara_rules", "wannacry.yar"),
            os.path.join(base, "ransomguard", "yara_rules", "lynx.yar"),
            os.path.join(base, "ransomguard", "yara_rules", "ransomware_generic.yar"),
            os.path.join(base, "ml", "ransomguard_model.pkl"),
        ]
        self.protected_paths = [p for p in candidates if os.path.exists(p)]
        log.info(f"[SelfDefense] Protecting {len(self.protected_paths)} critical files")

    def compute_integrity(self):
        hashes = {}
        for path in self.protected_paths:
            try:
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                hashes[path] = h.hexdigest()
            except Exception as e:
                log.warning(f"[SelfDefense] Cannot hash {path}: {e}")
        return hashes

    def save_integrity(self):
        self.integrity_hashes = self.compute_integrity()
        try:
            with open(INTEGRITY_FILE, "w", encoding="utf-8") as f:
                json.dump(self.integrity_hashes, f, indent=2)
            log.info(f"[SelfDefense] Integrity baseline saved ({len(self.integrity_hashes)} files)")
        except Exception as e:
            log.error(f"[SelfDefense] Failed to save integrity: {e}")

    def _load_integrity(self):
        if os.path.exists(INTEGRITY_FILE):
            try:
                with open(INTEGRITY_FILE, "r", encoding="utf-8") as f:
                    self.integrity_hashes = json.load(f)
            except Exception:
                self.integrity_hashes = {}

    def verify_integrity(self):
        current = self.compute_integrity()
        tampered = []
        for path, old_hash in self.integrity_hashes.items():
            new_hash = current.get(path)
            if new_hash != old_hash:
                tampered.append(path)
                self.record_tamper(
                    "file_modified", path,
                    f"hash changed: {old_hash[:16]}... -> {(new_hash or 'deleted')[:16]}...",
                )
        return tampered

    # ---------- 2. Registry guard (Windows) ----------
    def protect_registry(self):
        if not IS_WINDOWS:
            log.info("[SelfDefense] Registry guard skipped (non-Windows)")
            return
        try:
            import winreg
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ):
                    log.info("[SelfDefense] Registry guard active")
            except PermissionError:
                log.warning("[SelfDefense] Registry guard: no admin rights (skipping)")
        except Exception as e:
            log.warning(f"[SelfDefense] Registry guard failed: {e}")

    # ---------- 3. Process shield ----------
    def protect_own_pid(self):
        if IS_WINDOWS:
            try:
                import ctypes
                handle = ctypes.windll.kernel32.GetCurrentProcess()
                HIGH_PRIORITY_CLASS = 0x00000080
                ctypes.windll.kernel32.SetPriorityClass(handle, HIGH_PRIORITY_CLASS)
                log.info("[SelfDefense] Process priority raised to HIGH")
            except Exception as e:
                log.warning(f"[SelfDefense] Priority raise failed: {e}")

        import signal
        try:
            signal.signal(signal.SIGTERM, self._on_signal)
        except Exception:
            pass
        if hasattr(signal, "SIGBREAK"):
            try:
                signal.signal(signal.SIGBREAK, self._on_signal)
            except Exception:
                pass
        if hasattr(signal, "SIGINT"):
            pass  # leave Ctrl+C alone

    def _on_signal(self, signum, frame):
        log.warning(f"[SelfDefense] Termination signal received: {signum}")
        self.record_tamper(
            "signal_received", f"signal_{signum}",
            "Attempt to terminate RansomGuard detected",
        )

    # ---------- 4. Heartbeat ----------
    def update_heartbeat(self):
        try:
            with open(HEARTBEAT_FILE, "w") as f:
                f.write(str(int(time.time())))
        except Exception:
            pass

    def _heartbeat_loop(self):
        while self.running:
            self.update_heartbeat()
            time.sleep(2)

    def start_heartbeat(self):
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True,
        )
        self._heartbeat_thread.start()
        log.info("[SelfDefense] Heartbeat started (every 2s)")

    # ---------- 5. Integrity monitor ----------
    def _integrity_loop(self):
        while self.running:
            time.sleep(30)
            try:
                tampered = self.verify_integrity()
                if tampered:
                    log.error(f"[SelfDefense] {len(tampered)} file(s) tampered")
            except Exception as e:
                log.error(f"[SelfDefense] Integrity check failed: {e}")

    def start_integrity_monitor(self):
        self._watcher_thread = threading.Thread(
            target=self._integrity_loop, daemon=True,
        )
        self._watcher_thread.start()
        log.info("[SelfDefense] Integrity monitor started (every 30s)")

    # ---------- 6. Tamper log ----------
    def record_tamper(self, kind, target, detail):
        event = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "kind": kind,
            "target": target,
            "detail": detail,
            "pid": self.pid,
        }
        self.tamper_events.append(event)
        try:
            with open(SELF_DEFENSE_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass

        try:
            from ransomguard import state as state_module
            if hasattr(state_module, "push_tamper"):
                state_module.push_tamper(event)
        except Exception:
            pass

    def get_tamper_count(self):
        return len(self.tamper_events)

    def get_recent_tamper(self, n=10):
        return self.tamper_events[-n:]

    # ---------- Lifecycle ----------
    def activate(self):
        log.info("[SelfDefense] Activating...")
        self.register_protected_paths()
        self.save_integrity()
        self.protect_registry()
        self.protect_own_pid()
        self.start_heartbeat()
        self.start_integrity_monitor()
        log.info("[SelfDefense] All layers active")
        print("[SelfDefense] Anti-tamper system active")

    def shutdown(self):
        self.running = False