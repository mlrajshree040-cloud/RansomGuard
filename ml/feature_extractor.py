import time
from collections import deque
from ransomguard import config


class FeatureExtractor:
    """
    Maintains a sliding window of file events and extracts
    a feature vector for the ML classifier.

    Features:
      0. ops_per_sec        — file operations per second (rate)
      1. unique_exts        — number of distinct extensions touched
      2. renames            — rename/move events (strong ransomware signal)
      3. ext_changes        — count of files gaining a new extension
      4. decoy_touches      — number of decoy files touched
      5. avg_entropy        — average entropy of recently touched files
    """

    def __init__(self, decoy_manager, window_seconds=5, maxlen=500):
        self.decoy_manager = decoy_manager
        self.window = window_seconds
        self.events = deque(maxlen=maxlen)  # (timestamp, event_type, src, dest)

    def push(self, event_type, src_path, dest_path=None, entropy=None):
        self.events.append((time.time(), event_type, src_path, dest_path, entropy))
        self._prune()

    def _prune(self):
        now = time.time()
        while self.events and now - self.events[0][0] > self.window:
            self.events.popleft()

    def extract(self):
        if not self.events:
            return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

        now = time.time()
        oldest = self.events[0][0]
        duration = max(now - oldest, 0.001)

        ops_per_sec = len(self.events) / duration

        exts = set()
        renames = 0
        ext_changes = 0
        decoy_touches = 0
        entropies = []

        for ts, etype, src, dest, ent in self.events:
            # Extensions touched
            if src:
                import os
                e = os.path.splitext(src)[1].lower()
                if e:
                    exts.add(e)

            # Rename/move
            if etype in ("moved", "renamed"):
                renames += 1

            # Extension change (e.g., .docx → .docx.locked)
            if dest:
                import os
                src_ext = os.path.splitext(src or "")[1].lower()
                dst_ext = os.path.splitext(dest)[1].lower()
                if src_ext != dst_ext:
                    ext_changes += 1

            # Decoy touch
            if self.decoy_manager.is_decoy(src or ""):
                decoy_touches += 1

            # Entropy
            if ent is not None:
                entropies.append(ent)

        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0

        return [
            float(ops_per_sec),
            float(len(exts)),
            float(renames),
            float(ext_changes),
            float(decoy_touches),
            float(avg_entropy),
        ]

    def reset(self):
        self.events.clear()

    @staticmethod
    def feature_names():
        return [
            "ops_per_sec",
            "unique_exts",
            "renames",
            "ext_changes",
            "decoy_touches",
            "avg_entropy",
        ]