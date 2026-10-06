"""
Train the Random Forest classifier.

Run:
    python -m ml.generate_dataset
    python -m ml.train_model
Output:
    ml/ransomguard_model.pkl
"""
import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score,
)


DATASET = os.path.join(os.path.dirname(__file__), "dataset.csv")
MODEL   = os.path.join(os.path.dirname(__file__), "ransomguard_model.pkl")


def main():
    print("[Train] Loading dataset...")
    df = pd.read_csv(DATASET)

    X = df.drop("label", axis=1)
    y = df["label"]

    print(f"[Train] Rows: {len(df)}  Features: {list(X.columns)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    print("[Train] Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)

    print("\n" + "=" * 60)
    print(f"  Accuracy:  {acc * 100:.2f}%")
    print(f"  ROC-AUC:   {auc:.4f}")
    print("=" * 60)
    print("\nClassification Report:\n")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Ransomware"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Feature importance
    print("\nFeature Importance:")
    for name, imp in sorted(
        zip(X.columns, model.feature_importances_),
        key=lambda x: -x[1],
    ):
        bar = "█" * int(imp * 40)
        print(f"  {name:<16s} {imp:.3f}  {bar}")

    # Save
    joblib.dump(model, MODEL)
    print(f"\n[Train] Model saved to {MODEL}")


if __name__ == "__main__":
    main()