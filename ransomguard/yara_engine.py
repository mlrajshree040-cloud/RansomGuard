import os
import time
from ransomguard.logger import log

# YARA is optional — graceful fallback if not installed
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


RULES_DIR = os.path.join(os.path.dirname(__file__), "yara_rules")


class YaraEngine:
    """
    YARA rules engine for signature-based malware detection.

    - Compiles all .yar files in ransomguard/yara_rules/
    - Scans files against compiled rules
    - Returns matched rule names, severity, and family info
    """

    def __init__(self, rules_dir=None):
        self.rules_dir = rules_dir or RULES_DIR
        self.rules = None
        self.rule_metadata = {}   # rule_name -> metadata dict
        self._compile()

    # ---------- Compile ----------
    def _compile(self):
        if not YARA_AVAILABLE:
            log.warning("[YARA] yara-python not installed. "
                        "YARA detection disabled. "
                        "Install: pip install yara-python")
            return

        if not os.path.exists(self.rules_dir):
            log.warning(f"[YARA] Rules dir not found: {self.rules_dir}")
            return

        # Collect all .yar/.yara files
        rule_files = {}
        for fname in os.listdir(self.rules_dir):
            if fname.endswith((".yar", ".yara")):
                path = os.path.join(self.rules_dir, fname)
                rule_files[fname] = path

        if not rule_files:
            log.warning("[YARA] No .yar files found.")
            return

        try:
            # Compile all rule files into one ruleset
            self.rules = yara.compile(filepaths=rule_files)
            log.info(f"[YARA] Compiled {len(rule_files)} rule files.")
            print(f"[YARA] Compiled {len(rule_files)} rule files")
        except yara.SyntaxError as e:
            log.error(f"[YARA] Syntax error in rules: {e}")
            # Try compiling individually to find the bad file
            for name, path in rule_files.items():
                try:
                    yara.compile(filepath=path)
                except Exception as ex:
                    log.error(f"[YARA] Failed rule file: {name} — {ex}")
        except Exception as e:
            log.error(f"[YARA] Compile failed: {e}")

    # ---------- Scan ----------
    def scan_file(self, path, timeout=10):
        """
        Scan a single file against compiled YARA rules.
        Returns dict:
          {
            "matched": bool,
            "rules": [{"name":..., "meta":...}, ...],
            "error": str or None
          }
        """
        if not self.rules:
            return {"matched": False, "rules": [], "error": "no_rules"}

        try:
            matches = self.rules.match(path, timeout=timeout)
        except yara.TimeoutError:
            return {"matched": False, "rules": [], "error": "timeout"}
        except yara.Error as e:
            return {"matched": False, "rules": [], "error": str(e)}
        except Exception as e:
            return {"matched": False, "rules": [], "error": str(e)}

        results = []
        for m in matches:
            meta = dict(m.meta) if m.meta else {}
            results.append({
                "name": m.rule,
                "meta": meta,
                "namespace": m.namespace,
            })

        return {
            "matched": len(results) > 0,
            "rules": results,
            "error": None,
        }

    # ---------- Info ----------
    def is_ready(self):
        return self.rules is not None

    def rule_count(self):
        if not self.rules:
            return 0
        try:
            return len(self.rules)
        except Exception:
            return 0