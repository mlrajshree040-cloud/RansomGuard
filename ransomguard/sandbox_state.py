from threading import Lock
import time

_lock = Lock()

sandbox_state = {
    "running": False,
    "current_file": "",
    "started_at": 0,
    "last_result": None,
    "history": [],
}


def start_detonation(file_path):
    with _lock:
        sandbox_state["running"] = True
        sandbox_state["current_file"] = file_path
        sandbox_state["started_at"] = time.time()


def finish_detonation(result_dict):
    with _lock:
        sandbox_state["running"] = False
        sandbox_state["current_file"] = ""
        sandbox_state["last_result"] = result_dict
        sandbox_state["history"].append(result_dict)
        if len(sandbox_state["history"]) > 20:
            sandbox_state["history"] = sandbox_state["history"][-20:]


def get_state():
    with _lock:
        return dict(sandbox_state)