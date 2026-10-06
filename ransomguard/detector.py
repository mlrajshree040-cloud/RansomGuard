import os
import time
from collections import deque
from ransomguard import config, state
from ransomguard.entropy import file_entropy

# ML (optional)
try:
    from ml.feature_extractor import FeatureExtractor
    from ml.ml_detector import MLDetector
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

# YARA (optional)
try:
    from ransomguard.yara_engine import YaraEngine
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False


class ThreatDetector:
    def __init__(self, decoy_manager, honeypot_manager=None):
        self.decoy_manager = decoy_manager
        self.honeypot_manager = honeypot_manager
        self.recent_events = deque()
        self.flagged_paths = set()

        self.ml = None
        self.extractor = None
        if ML_AVAILABLE:
            try:
                self.ml = MLDetector(threshold=0.8)
                self.extractor = FeatureExtractor(decoy_manager)
            except Exception:
                self.ml = None
                self.extractor = None

        self.yara = None
        if YARA_AVAILABLE:
            try:
                self.yara = YaraEngine()
            except Exception:
                self.yara = None

    def _prune(self, now):
        window = config.THRESHOLDS["time_window_seconds"]
        while self.recent_events and now - self.recent_events[0][0] > window:
            self.recent_events.popleft()

    def analyze(self, event_type, src_path, dest_path=None):
        now = time.time()
        self.recent_events.append((now, src_path, event_type))
        self._prune(now)

        if not self.decoy_manager.is_decoy(src_path):
            self.flagged_paths.add(src_path)

        reasons = []
        severity = 0

        # ---------- 🍯 HONEYPOT (200) ----------
        if self.honeypot_manager and self.honeypot_manager.is_honeypot(src_path):
            reasons.append(f"HONEYPOT TOUCHED: {os.path.basename(src_path)}")
            severity += 200

        if (dest_path and self.honeypot_manager
                and self.honeypot_manager.is_honeypot(dest_path)):
            reasons.append(f"HONEYPOT RENAME TARGET: {os.path.basename(dest_path)}")
            severity += 200

        # ---------- 🍯 DECOY (100) ----------
        if self.decoy_manager.is_decoy(src_path):
            reasons.append(f"DECOY TOUCHED: {os.path.basename(src_path)}")
            severity += 100

        # ---------- MASS FILE OPS (40) ----------
        if len(self.recent_events) >= config.THRESHOLDS["mass_modify_count"]:
            reasons.append(
                f"Mass file ops: {len(self.recent_events)} "
                f"in {config.THRESHOLDS['time_window_seconds']}s"
            )
            severity += 40

        # ---------- RANSOMWARE EXTENSION (60) ----------
        check_path = dest_path if dest_path else src_path
        ext = os.path.splitext(check_path)[1].lower()
        if ext in config.RANSOMWARE_EXTENSIONS:
            reasons.append(f"Ransomware extension: {ext}")
            severity += 60

        # ---------- ENTROPY (30) ----------
        entropy_val = None
        if os.path.isfile(src_path) and not self.decoy_manager.is_decoy(src_path):
            try:
                entropy_val = file_entropy(src_path)
                if entropy_val >= config.THRESHOLDS["entropy_threshold"]:
                    reasons.append(f"High entropy: {entropy_val:.2f}")
                    severity += 30
            except Exception:
                pass

        # ---------- 🛡️ YARA (80) ----------
        if self.yara and self.yara.is_ready() and os.path.isfile(src_path):
            try:
                result = self.yara.scan_file(src_path)
                if result["matched"]:
                    for rule in result["rules"]:
                        rule_name = rule["name"]
                        meta = rule.get("meta", {})
                        family = meta.get("family", "unknown")
                        rseverity = meta.get("severity", "high")
                        reasons.append(f"YARA MATCH: {rule_name} (family: {family})")

                        # Push to dashboard state
                        try:
                            state.push_yara_match({
                                "rule": rule_name,
                                "family": family,
                                "severity": str(rseverity),
                                "file": os.path.basename(src_path),
                                "path": src_path,
                                "time": time.strftime("%H:%M:%S"),
                            })
                        except Exception:
                            pass
                    severity += 80
            except Exception:
                pass

        # ---------- 🤖 ML (50) ----------
        ml_result = None
        if self.ml and self.extractor and self.ml.is_ready():
            try:
                self.extractor.push(event_type, src_path, dest_path, entropy_val)
                features = self.extractor.extract()
                ml_result = self.ml.predict(features)
                if ml_result["verdict"] == "RANSOMWARE":
                    reasons.append(f"ML classifier: {ml_result['prob']*100:.1f}% ransomware")
                    severity += 50
                elif ml_result["verdict"] == "SUSPICIOUS":
                    reasons.append(f"ML classifier: {ml_result['prob']*100:.1f}% suspicious")
                    severity += 20
            except Exception:
                pass

        if severity >= 50:
            return {
                "severity": severity,
                "reasons": reasons,
                "paths": list(self.flagged_paths),
                "timestamp": now,
                "ml": ml_result,
            }
        return None

    def reset(self):
        self.recent_events.clear()
        self.flagged_paths.clear()
        if self.extractor:
            self.extractor.reset()