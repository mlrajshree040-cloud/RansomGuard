import os
import time
import threading
import traceback
from ransomguard import config, state
from ransomguard.decoy_manager import DecoyManager
from ransomguard.honeypot import HoneypotManager
from ransomguard.quarantine import QuarantineManager
from ransomguard.monitor import FileMonitor
from ransomguard.detector import ThreatDetector
from ransomguard.response import ResponseEngine
from ransomguard.rollback import RollbackEngine
from ransomguard.web_dashboard import start_dashboard
from ransomguard.selfdefense import SelfDefense
from ransomguard.screenshot import get_capture
from ransomguard.sandbox import get_sandbox
from ransomguard.logger import log
from ransomguard import dashboard


class RansomGuard:
    def __init__(self):
        self.folders = config.PROTECTED_FOLDERS
        self.decoy_managers = [DecoyManager(f) for f in self.folders]
        self.honeypot_manager = HoneypotManager()
        self.quarantine = QuarantineManager()

        self.detector = ThreatDetector(
            self.decoy_managers[0], self.honeypot_manager,
        )
        self.detector._all_decoy_managers = self.decoy_managers

        self.response = ResponseEngine(self.folders[0])
        self.rollback = RollbackEngine(self.folders, config.VAULT_FOLDER)

        self.monitor = FileMonitor(
            self.folders,
            self.on_event,
            honeypot_folder=self.honeypot_manager.folder(),
        )

        self.selfdefense = SelfDefense()
        self.screenshot = get_capture()
        self.sandbox = get_sandbox()

        self.contained = False
        self.last_containment_time = 0
        self.cooldown_seconds = 5

    def _is_any_decoy(self, path):
        return any(dm.is_decoy(path) for dm in self.decoy_managers)

    def on_event(self, event_type, src_path, dest_path=None):
        if self.contained:
            return
        if time.time() - self.last_containment_time < self.cooldown_seconds:
            return
        try:
            log.info(f"Event: {event_type} — {src_path}")
            threat = self.detector.analyze(event_type, src_path, dest_path)
            if threat:
                self.contained = True
                threading.Thread(
                    target=self._safe_handle_threat,
                    args=(threat,), daemon=True,
                ).start()
        except Exception as e:
            log.error(f"[on_event] Error: {e}")
            log.error(traceback.format_exc())

    def _safe_handle_threat(self, threat):
        try:
            self.handle_threat(threat)
        except Exception as e:
            log.error(f"[_safe_handle_threat] FATAL: {e}")
            log.error(traceback.format_exc())
        finally:
            time.sleep(3)
            self.contained = False
            self.last_containment_time = time.time()
            try: self.detector.reset()
            except Exception: pass
            try: state.clear_threat()
            except Exception: pass
            dashboard.show_info("System reset — ready for next attack.")

    def handle_threat(self, threat):
        state.set_threat(threat)
        dashboard.show_threat(threat)
        log.warning(f"THREAT severity={threat['severity']}")

        # 1. Screenshot
        try:
            path = self.screenshot.capture(tag="attack")
            if path:
                state.push_screenshot({
                    "filename": os.path.basename(path),
                    "path": path,
                    "time": time.strftime("%H:%M:%S"),
                    "reason": threat["reasons"][0] if threat.get("reasons") else "threat",
                })
                log.warning(f"[Screenshot] Saved to {path}")
        except Exception as e:
            log.error(f"[Screenshot] Capture failed: {e}")

        # 2. Auto-detonate in sandbox (severity >= 100)
        try:
            if threat["severity"] >= 100:
                for p in threat["paths"]:
                    if os.path.exists(p) and os.path.splitext(p)[1].lower() in config.RANSOMWARE_EXTENSIONS:
                        def run_sb(path=p):
                            try:
                                state.set_sandbox_running(True)
                                result = self.sandbox.detonate(path, timeout=5)
                                state.push_sandbox_result({
                                    **result.to_dict(),
                                    "time": time.strftime("%H:%M:%S"),
                                })
                            except Exception as e:
                                log.error(f"[Sandbox] {e}")
                            finally:
                                state.set_sandbox_running(False)
                        threading.Thread(target=run_sb, daemon=True).start()
                        break
        except Exception as e:
            log.error(f"[Sandbox] Auto-detonation failed: {e}")

        killed, unlocked = [], 0
        rollback_result = {"restored":0,"removed_rogue":0,"failed":0,"timestamp":"-"}
        snap = "-"
        quarantined = []

        try:
            killed = self.response.kill_processes_touching(threat["paths"])
        except Exception as e:
            log.error(f"kill failed: {e}")

        try:
            for path in threat["paths"]:
                if os.path.exists(path) and not self._is_any_decoy(path):
                    ext = os.path.splitext(path)[1].lower()
                    if ext in config.RANSOMWARE_EXTENSIONS:
                        entry = self.quarantine.quarantine_file(
                            path, reason="ransomware-extension"
                        )
                        if entry:
                            quarantined.append(entry)
        except Exception as e:
            log.error(f"quarantine failed: {e}")

        try:
            for f in self.folders:
                unlocked += self.response.unlock_folder(f)
        except Exception as e:
            log.error(f"unlock failed: {e}")

        try:
            rollback_result = self.rollback.restore()
        except Exception as e:
            log.error(f"rollback failed: {e}")

        try:
            snap = self.response.snapshot_paths(threat["paths"])
        except Exception as e:
            log.error(f"snapshot failed: {e}")

        try:
            live = self.rollback.current_manifest()
            state.refresh_integrity(live)
        except Exception as e:
            log.error(f"integrity refresh failed: {e}")

        try:
            state.set_quarantine_count(self.quarantine.count())
        except Exception:
            pass

        try:
            state.set_contained(rollback_result)
            dashboard.show_containment(killed, unlocked, snap)
        except Exception as e:
            log.error(f"dashboard update failed: {e}")

        try:
            time.sleep(1)
            for dm in self.decoy_managers:
                dm.restore()
        except Exception as e:
            log.error(f"decoy restore failed: {e}")

        try:
            self.honeypot_manager.restore()
        except Exception as e:
            log.error(f"honeypot restore failed: {e}")

    def start(self):
        dashboard.banner()

        try:
            self.selfdefense.activate()
            state.set_selfdefense_active(True)
        except Exception as e:
            log.error(f"[SelfDefense] Activation failed: {e}")

        for f in self.folders:
            os.makedirs(f, exist_ok=True)

        try:
            protected = self.rollback.snapshot()
        except Exception as e:
            log.error(f"Snapshot failed: {e}")
            protected = 0

        total_decoys = 0
        for dm in self.decoy_managers:
            try:
                decoys = dm.deploy()
                total_decoys += len(decoys)
            except Exception as e:
                log.error(f"Decoy deploy failed: {e}")
        dashboard.show_decoy_status(total_decoys)

        try:
            hp_files = self.honeypot_manager.deploy()
            print(f"[Honeypot] {hp_files} bait files deployed")
        except Exception as e:
            log.error(f"Honeypot deploy failed: {e}")

        try:
            state.set_integrity(
                self.rollback.manifest,
                vault_count=protected,
                decoy_count=total_decoys,
            )
            state.set_honeypot_count(len(config.HONEYPOT_SHARES))
            state.set_protected_folder_count(len(self.folders))
            state.set_quarantine_count(self.quarantine.count())
            state.set_screenshot_count(self.screenshot.count())
        except Exception as e:
            log.error(f"state init failed: {e}")

        dashboard.show_info(f"Protected folders: {len(self.folders)}")
        for f in self.folders:
            dashboard.show_info(f"  -> {f}")
        dashboard.show_info(f"Protected files in vault: {protected}")
        dashboard.show_info(f"Decoy files deployed: {total_decoys}")
        dashboard.show_info(f"Honeypot folder: {self.honeypot_manager.folder()}")
        dashboard.show_info(f"Quarantine folder: {config.QUARANTINE_FOLDER}")
        dashboard.show_info(f"Screenshots folder: {self.screenshot.folder}")

        start_dashboard(config.DASHBOARD_PORT)
        dashboard.show_info(f"Web dashboard: http://localhost:{config.DASHBOARD_PORT}")
        dashboard.show_info("Press Ctrl+C to stop.\n")

        self.monitor.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            dashboard.show_warn("Shutting down...")
            self.selfdefense.shutdown()
            self.monitor.stop()


if __name__ == "__main__":
    RansomGuard().start()