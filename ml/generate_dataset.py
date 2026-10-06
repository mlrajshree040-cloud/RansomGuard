"""
Generate a synthetic training dataset for the ML classifier.

Run: python -m ml.generate_dataset
Output: ml/dataset.csv  (2000 rows: 1000 benign + 1000 ransomware)
"""
import os
import csv
import random

random.seed(42)

OUT_PATH = os.path.join(os.path.dirname(__file__), "dataset.csv")

FIELDS = [
    "ops_per_sec",
    "unique_exts",
    "renames",
    "ext_changes",
    "decoy_touches",
    "avg_entropy",
    "label",   # 0 = benign, 1 = ransomware
]


def benign_sample():
    """Normal user behavior: low activity, few renames, no decoys."""
    return [
        random.uniform(0.05, 1.5),      # ops_per_sec
        random.randint(1, 2),            # unique_exts
        random.randint(0, 1),            # renames
        0,                               # ext_changes
        0,                               # decoy_touches
        random.uniform(2.0, 6.5),        # avg_entropy
        0,
    ]


def ransomware_sample():
    """Ransomware: high ops, many exts, many renames, decoy touches, high entropy."""
    return [
        random.uniform(8.0, 60.0),       # ops_per_sec
        random.randint(4, 15),           # unique_exts
        random.randint(3, 40),           # renames
        random.randint(3, 30),           # ext_changes
        random.choice([0, 1, 1, 2]),     # decoy_touches (usually ≥1)
        random.uniform(7.5, 8.0),        # avg_entropy
        1,
    ]


def main():
    rows = []
    for _ in range(1000):
        rows.append(benign_sample())
    for _ in range(1000):
        rows.append(ransomware_sample())

    random.shuffle(rows)

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(FIELDS)
        writer.writerows(rows)

    print(f"[Dataset] Wrote {len(rows)} rows to {OUT_PATH}")
    print(f"[Dataset] Benign: 1000  |  Ransomware: 1000")


if __name__ == "__main__":
    main()