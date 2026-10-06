import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def file_entropy(path: str, sample_size: int = 4096) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(sample_size)
        return shannon_entropy(data)
    except Exception:
        return 0.0