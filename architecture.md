# EX-HIDS Architecture

```
 Network + host events
          |
   Feature extraction (8 features)
     /                    \
Signature engine      Anomaly model
(5 named rules)       (z-score vs baseline)
     \                    /
          Fusion
  risk = 1 - (1 - sig) * (1 - anomaly)
          |
     Explainability layer
  - matched rule + reason
  - per-feature contribution
  - plain-English summary
          |
      Alert dashboard
```

## Modules
| File | Role |
|------|------|
| `js/engine.js` | Features, rules, anomaly scoring, fusion, attack simulators |
| `js/app.js` | Live stream, counters, explanation panel |
| `css/style.css` | Styling with light and dark themes |
| `ml/train_model.py` | Offline reference pipeline: Isolation Forest + Random Forest + SHAP |

## Why hybrid?
- Signature rules are precise and self-explanatory but miss unknown attacks.
- Anomaly detection finds unknown attacks but is noisy and hard to interpret.
- Fusing them, then attributing the score to features, gives coverage and transparency.

## Detection rules
| ID | Attack | Condition |
|----|--------|-----------|
| R101 | Port scan | 40+ distinct ports and SYN ratio above 0.6 |
| R102 | SSH brute force | 8+ failed logins |
| R103 | SYN flood | 500+ pkt/s and SYN ratio above 0.7 |
| R104 | Data exfiltration | 400+ KB out and under 20 KB in |
| R105 | Privilege escalation | 2+ privilege changes and 10+ spawned processes |
