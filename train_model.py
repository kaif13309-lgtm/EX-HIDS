"""EX-HIDS reference ML pipeline (offline).
Trains a hybrid model on synthetic data that mirrors the web demo's features:
  - Isolation Forest  -> anomaly score (catches unknown attacks)
  - Random Forest     -> supervised attack classifier (catches known attacks)
  - SHAP              -> explains the Random Forest's decisions
Replace make_data() with NSL-KDD or CICIDS2017 for real evaluation.
"""
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

FEATURES = ["pkt_rate", "src_bytes", "dst_bytes", "distinct_ports",
            "failed_logins", "syn_ratio", "proc_spawn", "priv_change"]
rng = np.random.default_rng(42)

def make_data(n=3000):
    normal = np.c_[rng.normal(40, 15, n), rng.normal(12, 6, n), rng.normal(30, 12, n),
                   rng.normal(2, 1.2, n), rng.binomial(1, .08, n), rng.normal(.08, .05, n),
                   rng.normal(2, 1.5, n), np.zeros(n)]
    m = n // 5
    scan = normal[:m].copy(); scan[:, 3] = rng.integers(40, 120, m); scan[:, 5] = .9
    brute = normal[m:2*m].copy(); brute[:, 4] = rng.integers(10, 40, m)
    flood = normal[2*m:3*m].copy(); flood[:, 0] = rng.integers(600, 1800, m); flood[:, 5] = .95
    exfil = normal[3*m:4*m].copy(); exfil[:, 1] = rng.integers(500, 1200, m); exfil[:, 2] = 6
    X = np.vstack([normal, scan, brute, flood, exfil]).clip(min=0)
    y = np.r_[np.zeros(n), np.ones(4 * m)]
    return X, y

def main():
    X, y = make_data()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.25, random_state=1, stratify=y)

    iso = IsolationForest(contamination=.1, random_state=1).fit(Xtr[ytr == 0])
    rf = RandomForestClassifier(n_estimators=150, random_state=1).fit(Xtr, ytr)

    # Fusion: flag if either detector flags
    pred = ((rf.predict(Xte) == 1) | (iso.predict(Xte) == -1)).astype(int)
    print(classification_report(yte, pred, target_names=["normal", "attack"]))

    try:
        import shap
        sv = shap.TreeExplainer(rf).shap_values(Xte[:200])
        sv = sv[1] if isinstance(sv, list) else sv[..., 1]
        imp = np.abs(sv).mean(axis=0)
        print("Mean |SHAP| per feature:")
        for f, v in sorted(zip(FEATURES, imp), key=lambda t: -t[1]):
            print(f"  {f:15s} {v:.4f}")
    except ImportError:
        print("Install shap to see explanations: pip install shap")

if __name__ == "__main__":
    main()
