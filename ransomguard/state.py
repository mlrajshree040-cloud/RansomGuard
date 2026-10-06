from collections import deque
from threading import Lock

_lock = Lock()

state = {
    "events": deque(maxlen=100),
    "threat": None,
    "contained": False,
    "rollback": None,
    "status": "SAFE",
    "integrity": {},
    "vault_files": 0,
    "decoys": 0,
    "honeypot_shares": 0,
    "quarantine_count": 0,
    "protected_folders": 0,
    "yara_count": 0,
    "yara_matches": deque(maxlen=50),
    "tamper_count": 0,
    "tamper_events": deque(maxlen=30),
    "selfdefense_active": False,
    "screenshot_count": 0,
    "screenshots": deque(maxlen=20),
    "sandbox_running": False,
    "sandbox_last": None,
    "sandbox_count": 0,
    "sandbox_history": deque(maxlen=10),
}


def push_event(event):
    with _lock:
        state["events"].appendleft(event)


def set_threat(threat):
    with _lock:
        state["threat"] = threat
        state["status"] = "THREAT"


def set_contained(rollback_info):
    with _lock:
        state["contained"] = True
        state["rollback"] = rollback_info
        state["status"] = "CONTAINED"


def set_integrity(manifest, vault_count, decoy_count):
    with _lock:
        state["integrity"] = dict(manifest)
        state["vault_files"] = vault_count
        state["decoys"] = decoy_count


def refresh_integrity(manifest):
    with _lock:
        state["integrity"] = dict(manifest)


def set_honeypot_count(count):
    with _lock:
        state["honeypot_shares"] = count


def set_quarantine_count(count):
    with _lock:
        state["quarantine_count"] = count


def set_protected_folder_count(count):
    with _lock:
        state["protected_folders"] = count


def push_yara_match(match):
    with _lock:
        state["yara_count"] += 1
        state["yara_matches"].appendleft(match)


def get_yara_count():
    with _lock:
        return state["yara_count"]


def reset_yara():
    with _lock:
        state["yara_count"] = 0
        state["yara_matches"].clear()


def push_tamper(event):
    with _lock:
        state["tamper_count"] += 1
        state["tamper_events"].appendleft(event)


def set_selfdefense_active(active):
    with _lock:
        state["selfdefense_active"] = bool(active)


def push_screenshot(entry):
    with _lock:
        state["screenshot_count"] += 1
        state["screenshots"].appendleft(entry)


def set_screenshot_count(count):
    with _lock:
        state["screenshot_count"] = count


def set_sandbox_running(running):
    with _lock:
        state["sandbox_running"] = bool(running)


def push_sandbox_result(result):
    with _lock:
        state["sandbox_count"] += 1
        state["sandbox_last"] = result
        state["sandbox_history"].appendleft(result)


def clear_threat():
    with _lock:
        state["threat"] = None
        state["contained"] = False
        state["rollback"] = None
        state["status"] = "SAFE"


def snapshot():
    with _lock:
        return {
            "events": list(state["events"]),
            "threat": state["threat"],
            "contained": state["contained"],
            "rollback": state["rollback"],
            "status": state["status"],
            "integrity": state["integrity"],
            "vault_files": state["vault_files"],
            "decoys": state["decoys"],
            "honeypot_shares": state["honeypot_shares"],
            "quarantine_count": state["quarantine_count"],
            "protected_folders": state["protected_folders"],
            "yara_count": state["yara_count"],
            "yara_matches": list(state["yara_matches"]),
            "tamper_count": state["tamper_count"],
            "tamper_events": list(state["tamper_events"]),
            "selfdefense_active": state["selfdefense_active"],
            "screenshot_count": state["screenshot_count"],
            "screenshots": list(state["screenshots"]),
            "sandbox_running": state["sandbox_running"],
            "sandbox_last": state["sandbox_last"],
            "sandbox_count": state["sandbox_count"],
            "sandbox_history": list(state["sandbox_history"]),
        }