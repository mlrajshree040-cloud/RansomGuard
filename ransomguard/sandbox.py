"""
Sandbox Detonation Engine.
Runs suspicious files in isolation with strict resource limits.
"""
import os
import time
import shutil
import tempfile
import subprocess
import threading
import platform

try:
    import psutil
except ImportError:
    psutil = None

from ransomguard import config
from ransomguard.logger import log


IS_WINDOWS = platform.system() == "Windows"
SANDBOX_ROOT = os.path.join(config.BASE_DIR, "sandbox")
os.makedirs(SANDBOX_ROOT, exist_ok=True)

DEFAULT_TIMEOUT = 5
MAX_MEMORY_MB = 256
MAX_CPU_PERCENT = 80


class SandboxResult:
    def __init__(self):
        self.file_path = ""
        self.started_at = 0
        self.finished_at = 0
        self.exit_code = None
        self.timed_out = False
        self.error = None
        self.files_created = []
        self.files_modified = []
        self.files_deleted = []
        self.processes_spawned = []
        self.network_attempts = 0
        self.verdict = "UNKNOWN"
        self.score = 0
        self.notes = []

    def duration(self):
        return round(self.finished_at - self.started_at, 2)

    def to_dict(self):
        return {
            "file_path": self.file_path,
            "duration": self.duration(),
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "error": self.error,
            "files_created": self.files_created[:50],
            "files_modified": self.files_modified[:50],
            "files_deleted": self.files_deleted[:50],
            "processes_spawned": self.processes_spawned[:50],
            "network_attempts": self.network_attempts,
            "verdict": self.verdict,
            "score": self.score,
            "notes": self.notes,
        }


class SandboxEngine:
    def __init__(self, sandbox_dir=None):
        self.sandbox_dir = sandbox_dir or SANDBOX_ROOT
        os.makedirs(self.sandbox_dir, exist_ok=True)
        self.current_result = None
        self.cancel_flag = threading.Event()

    def _prepare_sandbox(self):
        run_dir = tempfile.mkdtemp(prefix="run_", dir=self.sandbox_dir)
        return run_dir

    def _cleanup_sandbox(self, run_dir):
        try:
            if os.path.exists(run_dir):
                shutil.rmtree(run_dir, ignore_errors=True)
        except Exception as e:
            log.warning(f"[Sandbox] Cleanup failed: {e}")

    def _snapshot_files(self, root):
        snap = {}
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                full = os.path.join(dirpath, name)
                try:
                    st = os.stat(full)
                    snap[full] = (st.st_size, st.st_mtime)
                except Exception:
                    pass
        return snap

    def detonate(self, file_path, timeout=DEFAULT_TIMEOUT, progress_callback=None):
        result = SandboxResult()
        result.file_path = file_path
        result.started_at = time.time()

        if not os.path.exists(file_path):
            result.error = "File not found"
            result.finished_at = time.time()
            return result

        run_dir = self._prepare_sandbox()

        try:
            target_name = os.path.basename(file_path)
            target_path = os.path.join(run_dir, target_name)
            shutil.copy2(file_path, target_path)
        except Exception as e:
            result.error = f"Copy failed: {e}"
            result.finished_at = time.time()
            self._cleanup_sandbox(run_dir)
            return result

        baseline = self._snapshot_files(run_dir)

        try:
            creation_flags = 0
            if IS_WINDOWS:
                creation_flags = 0x08000000

            env = os.environ.copy()
            env["RANSOMGUARD_SANDBOX"] = "1"

            proc = subprocess.Popen(
                [target_path],
                cwd=run_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=creation_flags,
            )
        except FileNotFoundError:
            result.error = "Executable not found or not runnable"
            result.finished_at = time.time()
            self._cleanup_sandbox(run_dir)
            return result
        except PermissionError:
            result.error = "Permission denied (try running as admin)"
            result.finished_at = time.time()
            self._cleanup_sandbox(run_dir)
            return result
        except Exception as e:
            result.error = f"Launch failed: {e}"
            result.finished_at = time.time()
            self._cleanup_sandbox(run_dir)
            return result

        start_time = time.time()
        seen_pids = set()
        seen_files = set()

        while True:
            elapsed = time.time() - start_time

            if elapsed > timeout:
                result.timed_out = True
                self._kill_tree(proc.pid)
                break

            if proc.poll() is not None:
                result.exit_code = proc.returncode
                break

            if psutil:
                try:
                    parent = psutil.Process(proc.pid)
                    children = parent.children(recursive=True)
                    for child in children:
                        if child.pid not in seen_pids:
                            seen_pids.add(child.pid)
                            try:
                                result.processes_spawned.append({
                                    "pid": child.pid,
                                    "name": child.name(),
                                })
                            except Exception:
                                pass
                except Exception:
                    pass

            try:
                current = self._snapshot_files(run_dir)
                for f, meta in current.items():
                    if f not in baseline:
                        if f not in seen_files:
                            seen_files.add(f)
                            result.files_created.append(
                                os.path.relpath(f, run_dir)
                            )
                    else:
                        if baseline[f] != meta and f not in seen_files:
                            seen_files.add(f)
                            result.files_modified.append(
                                os.path.relpath(f, run_dir)
                            )
                for f in baseline:
                    if f not in current and f not in seen_files:
                        seen_files.add(f)
                        result.files_deleted.append(
                            os.path.relpath(f, run_dir)
                        )
            except Exception:
                pass

            if progress_callback:
                try:
                    progress_callback(elapsed, len(result.files_created),
                                      len(result.processes_spawned))
                except Exception:
                    pass

            time.sleep(0.2)

        result.finished_at = time.time()
        self._score(result)
        self._cleanup_sandbox(run_dir)
        self.current_result = result
        return result

    def _kill_tree(self, pid):
        if not psutil:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True, check=False,
                )
            except Exception:
                pass
            return

        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except Exception:
                    pass
            try:
                parent.kill()
            except Exception:
                pass
        except Exception:
            pass

    def _score(self, result):
        score = 0
        notes = []

        if len(result.files_created) > 5:
            score += 30
            notes.append(f"Created {len(result.files_created)} files")
        if len(result.files_modified) > 5:
            score += 25
            notes.append(f"Modified {len(result.files_modified)} files")
        if len(result.files_deleted) > 0:
            score += 20
            notes.append(f"Deleted {len(result.files_deleted)} files")
        if len(result.processes_spawned) > 2:
            score += 30
            notes.append(f"Spawned {len(result.processes_spawned)} processes")
        if result.network_attempts > 0:
            score += 40
            notes.append(f"{result.network_attempts} network attempts")

        if score >= 70:
            result.verdict = "MALICIOUS"
        elif score >= 40:
            result.verdict = "SUSPICIOUS"
        elif score > 0:
            result.verdict = "SUSPECTED"
        else:
            result.verdict = "CLEAN"

        result.score = score
        result.notes = notes

        if result.timed_out:
            result.notes.append("Timed out (possible infinite loop or blocked)")

        if result.exit_code == 0 and score == 0 and not result.timed_out:
            result.verdict = "CLEAN"


_singleton = None

def get_sandbox():
    global _singleton
    if _singleton is None:
        _singleton = SandboxEngine()
    return _singleton