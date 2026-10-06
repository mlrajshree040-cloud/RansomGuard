import os
import psutil
from ransomguard import config


class ResponseEngine:
    def __init__(self, folder):
        self.folder = folder
        self.contained_pids = []
        self._protected_pids = {os.getpid(), os.getppid()}

    def _is_protected(self, pid):
        return pid in self._protected_pids or pid in (0, 4)

    def kill_processes_touching(self, paths):
        killed = []
        flagged = {os.path.abspath(p).lower() for p in paths}

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                if self._is_protected(pid):
                    continue

                try:
                    open_files = proc.open_files()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                except Exception:
                    continue

                for f in open_files:
                    try:
                        if os.path.abspath(f.path).lower() in flagged:
                            proc.kill()
                            killed.append((pid, proc.info["name"]))
                            self.contained_pids.append(pid)
                            break
                    except Exception:
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue
        return killed

    def unlock_folder(self, folder=None):
        folder = folder or self.folder
        count = 0
        for root, _, files in os.walk(folder):
            for name in files:
                try:
                    os.chmod(os.path.join(root, name), 0o644)
                    count += 1
                except Exception:
                    pass
        return count

    def snapshot_paths(self, paths):
        out = os.path.join(config.BASE_DIR, "incident_snapshot.txt")
        with open(out, "w", encoding="utf-8") as f:
            for p in paths:
                f.write(p + "\n")
        return out