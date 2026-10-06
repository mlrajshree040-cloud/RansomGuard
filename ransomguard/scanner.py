import os
import hashlib
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ransomguard import config, state
from ransomguard.entropy import file_entropy
from ransomguard.logger import log


# ========== Suspicious extensions (ransomware markers) ==========
SUSPICIOUS_EXTENSIONS = set(config.RANSOMWARE_EXTENSIONS) | {
    ".crypto", ".crinf", ".r5a", ".xrnt", ".xtbl", ".crypt",
    ".cerber", ".dharma", ".wallet", ".zzzzz", ".locky",
    ".vvv", ".ccc", ".ecc", ".exx", ".xyz", ".zzz",
}

# ========== Directories to never scan ==========
SKIP_DIRS = {
    "windows", "$recycle.bin", "system volume information",
    "programdata\\microsoft\\windows\\wer",
    "appdata\\local\\temp", "appdata\\local\\microsoft",
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "site-packages", "dist-packages", ".cache",
}

SKIP_EXTENSIONS = {
    ".sys", ".msi", ".cab", ".log", ".tmp",
    ".lock", ".db", ".iso", ".vhd", ".vhdx",
    ".pyc", ".pyo", ".pyd",
}

# ========== Whitelist: extensions that legitimately have high entropy ==========
EXPECTED_HIGH_ENTROPY = {
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".tar", ".tgz",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
    ".wav", ".flac", ".aac", ".ogg", ".m4a",
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
    ".pdf", ".epub", ".jar", ".apk", ".war", ".ear",
    ".exe", ".dll", ".so", ".dylib", ".sys", ".com",
    ".iso", ".img", ".cab", ".dmg", ".pkg", ".deb", ".rpm",
    ".woff", ".woff2", ".ttf", ".otf",
    ".psd", ".ai", ".sketch", ".blend",
}

# ========== Ransomware strings ==========
MALWARE_PATTERNS = [
    b"your files have been encrypted",
    b"all your files have been encrypted",
    b"send bitcoin",
    b"send btc",
    b"bitcoin address",
    b"tor browser",
    b"onion address",
    b"decrypt your files",
    b"pay the ransom",
    b"recover your files",
    b"your documents, photos, databases",
    b"how to buy bitcoin",
    b"decryption key",
    b"ransom note",
]

# ========== Dangerous double extensions ==========
EXE_EXTS = {"exe", "scr", "bat", "cmd", "vbs", "js", "ps1", "hta", "com", "pif"}
DOC_EXTS = {"pdf", "docx", "doc", "xlsx", "xls", "jpg", "jpeg", "png", "txt", "zip", "rar"}


class ScanResult:
    def __init__(self, path):
        self.path = path
        self.verdict = "SAFE"
        self.reasons = []
        self.size = 0
        self.sha256 = ""
        self.entropy = 0.0


class SystemScanner:
    def __init__(self, root_paths=None, max_workers=8):
        self.root_paths = root_paths or self._default_roots()
        self.max_workers = max_workers
        self.results = []
        self.threats = []
        self.scanned = 0
        self.skipped = 0
        self.start_time = 0
        self.end_time = 0
        self.progress_callback = None
        self.cancel_flag = threading.Event()

        # YARA engine (optional)
        self.yara = None
        try:
            from ransomguard.yara_engine import YaraEngine
            self.yara = YaraEngine()
        except Exception as e:
            log.warning(f"[Scanner] YARA engine not available: {e}")

    def _default_roots(self):
        user = os.path.expanduser("~")
        candidates = [
            os.path.join(user, "Downloads"),
            os.path.join(user, "Documents"),
            os.path.join(user, "Desktop"),
            os.path.join(user, "Pictures"),
            os.path.join(user, "Videos"),
            os.path.join(user, "Music"),
            config.PROTECTED_FOLDER,
        ]
        return [p for p in candidates if os.path.exists(p)]

    def _should_skip_dir(self, path):
        low = path.lower()
        return any(s in low for s in SKIP_DIRS)

    def _should_skip_file(self, path):
        ext = os.path.splitext(path)[1].lower()
        return ext in SKIP_EXTENSIONS

    def _sha256(self, path, max_bytes=2 * 1024 * 1024):
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                h.update(f.read(max_bytes))
            return h.hexdigest()
        except Exception:
            return ""

    def _contains_ransom_strings(self, path, max_bytes=64 * 1024):
        try:
            with open(path, "rb") as f:
                data = f.read(max_bytes).lower()
            for pattern in MALWARE_PATTERNS:
                if pattern.lower() in data:
                    return pattern.decode(errors="ignore")
        except Exception:
            pass
        return None

    def _has_double_extension(self, path):
        name = os.path.basename(path).lower()
        parts = name.split(".")
        if len(parts) >= 3:
            if parts[-1] in EXE_EXTS and parts[-2] in DOC_EXTS:
                return True
        return False

    def _analyze_file(self, path):
        r = ScanResult(path)

        try:
            r.size = os.path.getsize(path)
        except Exception:
            return None

        if r.size == 0:
            return None

        if r.size > 500 * 1024 * 1024:
            return None

        ext = os.path.splitext(path)[1].lower()

        # 1. Suspicious extension
        if ext in SUSPICIOUS_EXTENSIONS:
            r.reasons.append(f"Ransomware extension: {ext}")
            r.verdict = "MALICIOUS"

        # 2. Double extension
        if self._has_double_extension(path):
            r.reasons.append("Double extension (possible disguise)")
            r.verdict = "MALICIOUS"

        # 3. Ransomware strings
        match = self._contains_ransom_strings(path)
        if match:
            r.reasons.append(f"Ransomware string: '{match[:40]}'")
            r.verdict = "MALICIOUS"

        # 4. YARA signature scan
        if self.yara and self.yara.is_ready():
            try:
                yres = self.yara.scan_file(path)
                if yres["matched"]:
                    for rule in yres["rules"]:
                        rule_name = rule.get("name", "unknown")
                        meta = rule.get("meta", {})
                        family = meta.get("family", "unknown")
                        severity = meta.get("severity", "high")
                        r.reasons.append(
                            f"YARA: {rule_name} (family: {family})"
                        )

                        try:
                            state.push_yara_match({
                                "rule": rule_name,
                                "family": family,
                                "severity": str(severity),
                                "file": os.path.basename(path),
                                "path": path,
                                "time": time.strftime("%H:%M:%S"),
                            })
                        except Exception:
                            pass
                    r.verdict = "MALICIOUS"
            except Exception as e:
                log.warning(f"[Scanner] YARA scan failed for {path}: {e}")

        # 5. Entropy check
        if r.size < 50 * 1024 * 1024 and ext not in EXPECTED_HIGH_ENTROPY:
            try:
                ent = file_entropy(path)
                r.entropy = ent
                if ent > config.THRESHOLDS["entropy_threshold"]:
                    r.reasons.append(
                        f"High entropy: {ent:.2f} (possibly encrypted)"
                    )
                    if r.verdict == "SAFE":
                        r.verdict = "SUSPICIOUS"
            except Exception:
                pass

        # 6. SHA-256 for flagged files
        if r.verdict != "SAFE":
            r.sha256 = self._sha256(path)

        return r

    def _walk_targets(self):
        for root in self.root_paths:
            if not os.path.exists(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                if self.cancel_flag.is_set():
                    return
                if self._should_skip_dir(dirpath):
                    dirnames[:] = []
                    continue

                dirnames[:] = [
                    d for d in dirnames
                    if not self._should_skip_dir(os.path.join(dirpath, d))
                ]

                for fname in filenames:
                    full = os.path.join(dirpath, fname)
                    if self._should_skip_file(full):
                        self.skipped += 1
                        continue
                    yield full

    def scan(self, progress_callback=None):
        self.start_time = time.time()
        self.results = []
        self.threats = []
        self.scanned = 0
        self.skipped = 0
        self.cancel_flag.clear()
        self.progress_callback = progress_callback

        log.info(f"[Scanner] Starting scan on {len(self.root_paths)} targets")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for path in self._walk_targets():
                if self.cancel_flag.is_set():
                    break
                futures[executor.submit(self._analyze_file, path)] = path

            for fut in as_completed(futures):
                if self.cancel_flag.is_set():
                    break
                try:
                    r = fut.result()
                except Exception:
                    continue

                self.scanned += 1

                if r:
                    self.results.append(r)
                    if r.verdict in ("SUSPICIOUS", "MALICIOUS"):
                        self.threats.append(r)

                if self.progress_callback and self.scanned % 25 == 0:
                    try:
                        self.progress_callback(
                            self.scanned,
                            len(self.threats),
                            futures[fut],
                        )
                    except Exception:
                        pass

        self.end_time = time.time()
        duration = self.end_time - self.start_time

        log.info(
            f"[Scanner] Done — scanned={self.scanned}, "
            f"threats={len(self.threats)}, duration={duration:.1f}s"
        )

        return {
            "scanned": self.scanned,
            "skipped": self.skipped,
            "threats": len(self.threats),
            "duration": round(duration, 1),
            "threat_list": [self._threat_dict(t) for t in self.threats],
            "roots": self.root_paths,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def cancel(self):
        self.cancel_flag.set()

    def _threat_dict(self, r):
        return {
            "path": r.path,
            "name": os.path.basename(r.path),
            "verdict": r.verdict,
            "reasons": r.reasons,
            "size": r.size,
            "entropy": round(r.entropy, 2),
            "sha256": r.sha256,
        }