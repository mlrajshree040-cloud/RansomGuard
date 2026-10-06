import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ransomguard import state


class _Handler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_any_event(self, event):
        if event.is_directory:
            return
        state.push_event({
            "time": time.strftime("%H:%M:%S"),
            "type": event.event_type,
            "path": os.path.basename(event.src_path),
        })
        self.callback(
            event.event_type,
            event.src_path,
            getattr(event, "dest_path", None),
        )


class FileMonitor:
    """
    Watches MULTIPLE protected folders + the honeypot folder.
    """

    def __init__(self, folders, callback, honeypot_folder=None):
        if isinstance(folders, str):
            folders = [folders]
        self.folders = folders
        self.honeypot_folder = honeypot_folder
        self.callback = callback
        self.observer = Observer()

    def start(self):
        handler = _Handler(self.callback)

        for folder in self.folders:
            if not os.path.exists(folder):
                os.makedirs(folder, exist_ok=True)
            self.observer.schedule(handler, folder, recursive=True)
            print(f"[Monitor] Watching protected: {folder}")

        if self.honeypot_folder and os.path.exists(self.honeypot_folder):
            self.observer.schedule(
                handler, self.honeypot_folder, recursive=True,
            )
            print(f"[Monitor] Watching honeypot:  {self.honeypot_folder}")

        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()