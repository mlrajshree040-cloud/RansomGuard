from threading import Lock

_lock = Lock()

scan_state = {
    "running": False,
    "phase": "idle",
    "scanned": 0,
    "threats": 0,
    "current": "",
    "roots": [],
    "result": None,
}


def start_scan(roots):
    with _lock:
        scan_state["running"] = True
        scan_state["phase"] = "scanning"
        scan_state["scanned"] = 0
        scan_state["threats"] = 0
        scan_state["current"] = ""
        scan_state["roots"] = list(roots)
        scan_state["result"] = None


def update_progress(scanned, threats, current):
    with _lock:
        scan_state["scanned"] = scanned
        scan_state["threats"] = threats
        scan_state["current"] = current


def finish_scan(result):
    with _lock:
        scan_state["running"] = False
        scan_state["phase"] = "done"
        scan_state["result"] = result


def cancel_scan():
    with _lock:
        scan_state["running"] = False
        scan_state["phase"] = "cancelled"


def get_state():
    with _lock:
        return dict(scan_state)