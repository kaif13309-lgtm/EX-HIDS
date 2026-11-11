# EX-HIDS: Explainable Hybrid Intrusion Detection System

A prototype that combines signature-based and anomaly-based detection and explains every alert.

**Live demo:** `https://YOUR-USERNAME.github.io/EX-HIDS/`

## Features
- Signature engine with 5 named rules
- Anomaly model using z-scores on 8 network and host features
- Fusion: `risk = 1 - (1 - signature) * (1 - anomaly)`
- Explainability: matched rule, plain-English reason, SHAP-style feature contributions
- Live simulated stream with one-click attack injection, including an unknown "zero-day" case

## Project structure
```
EX-HIDS/
├── index.html          # dashboard page
├── css/style.css       # styling (light and dark)
├── js/engine.js        # detection engine
├── js/app.js           # UI logic
├── ml/train_model.py   # reference ML pipeline (Isolation Forest + Random Forest + SHAP)
├── docs/architecture.md
├── requirements.txt
├── LICENSE
└── README.md
```

## Run the web demo
Open `index.html` in a browser. No install needed.

## Run the ML pipeline
```bash
pip install -r requirements.txt
python ml/train_model.py
```

## Limitations
Traffic is simulated. For real evaluation, use NSL-KDD or CICIDS2017 and a trained model with SHAP or LIME.
