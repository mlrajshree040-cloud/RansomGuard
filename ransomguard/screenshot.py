"""
Screenshot capture on attack.
Uses Pillow's ImageGrab on Windows/macOS and PIL fallback on Linux.
Saves PNG files to C:\\RansomGuard\\screenshots\\
"""
import os
import time
from ransomguard import config
from ransomguard.logger import log


SCREENSHOT_FOLDER = os.path.join(config.BASE_DIR, "screenshots")
os.makedirs(SCREENSHOT_FOLDER, exist_ok=True)


def _try_import_grab():
    try:
        from PIL import ImageGrab
        return ImageGrab
    except Exception:
        return None


def _try_import_pyscreenshot():
    try:
        import pyscreenshot
        return pyscreenshot
    except Exception:
        return None


class ScreenshotCapture:
    def __init__(self, folder=None):
        self.folder = folder or SCREENSHOT_FOLDER
        os.makedirs(self.folder, exist_ok=True)

    def capture(self, tag="attack"):
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{tag}_{timestamp}.png"
        path = os.path.join(self.folder, filename)

        # Attempt 1: Pillow ImageGrab
        grab = _try_import_grab()
        if grab:
            try:
                try:
                    img = grab.grab(all_screens=True)
                except TypeError:
                    img = grab.grab()
                img.save(path, "PNG")
                log.warning(f"[Screenshot] Captured: {filename}")
                return path
            except Exception as e:
                log.warning(f"[Screenshot] ImageGrab failed: {e}")

        # Attempt 2: pyscreenshot
        ps = _try_import_pyscreenshot()
        if ps:
            try:
                img = ps.grab()
                img.save(path, "PNG")
                log.warning(f"[Screenshot] Captured: {filename}")
                return path
            except Exception as e:
                log.warning(f"[Screenshot] pyscreenshot failed: {e}")

        log.error("[Screenshot] No capture backend available "
                  "(install Pillow: pip install pillow)")
        return None

    def list_screenshots(self, limit=20):
        try:
            files = [
                os.path.join(self.folder, f)
                for f in os.listdir(self.folder)
                if f.lower().endswith(".png")
            ]
            files.sort(key=os.path.getmtime, reverse=True)
            return files[:limit]
        except Exception:
            return []

    def count(self):
        try:
            return len([f for f in os.listdir(self.folder)
                        if f.lower().endswith(".png")])
        except Exception:
            return 0


_singleton = None

def get_capture():
    global _singleton
    if _singleton is None:
        _singleton = ScreenshotCapture()
    return _singleton