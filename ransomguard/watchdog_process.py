"""
Watchdog Process — respawns RansomGuard if killed.

Run:
    python -m ransomguard.watchdog_process parent
"""
import os
import sys
import time
import subprocess

from ransomguard import config


HEARTBEAT_FILE = os.path.join(config.BASE_DIR, ".rg_heartbeat")
HEARTBEAT_TIMEOUT = 10
CHECK_INTERVAL = 3


def heartbeat_age():
    if not os.path.exists(HEARTBEAT_FILE):
        return 9999
    try:
        with open(HEARTBEAT_FILE) as f:
            last = int(f.read().strip())
        return int(time.time()) - last
    except Exception:
        return 9999


def parent_loop():
    print("[Watchdog] Parent started. Spawning child...")
    print(f"[Watchdog] Heartbeat file: {HEARTBEAT_FILE}")
    print(f"[Watchdog] Timeout: {HEARTBEAT_TIMEOUT}s")

    child = None
    respawn_count = 0

    def spawn():
        nonlocal child, respawn_count
        try:
            if os.path.exists(HEARTBEAT_FILE):
                os.remove(HEARTBEAT_FILE)
        except Exception:
            pass
        child = subprocess.Popen(
            [sys.executable, "main.py"],
            cwd=config.BASE_DIR,
        )
        respawn_count += 1
        print(f"[Watchdog] Child spawned (PID {child.pid}, spawn #{respawn_count})")

    spawn()

    while True:
        time.sleep(CHECK_INTERVAL)

        if child and child.poll() is not None:
            print(f"[Watchdog] Child died (exit {child.returncode}). Respawning...")
            time.sleep(2)
            spawn()
            continue

        age = heartbeat_age()
        if age > HEARTBEAT_TIMEOUT:
            print(f"[Watchdog] Heartbeat stale ({age}s). Respawning...")
            try:
                if child and child.poll() is None:
                    child.kill()
            except Exception:
                pass
            time.sleep(2)
            spawn()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "parent"
    if mode == "parent":
        try:
            parent_loop()
        except KeyboardInterrupt:
            print("\n[Watchdog] Shutting down.")
    else:
        os.execv(sys.executable, [sys.executable, "main.py"])


if __name__ == "__main__":
    main()