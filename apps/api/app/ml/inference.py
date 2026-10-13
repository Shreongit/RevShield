import os
import joblib
import numpy as np
from typing import Any, Dict, List
from app.ml.feature_extractor import FEATURE_NAMES, extract_features_from_url

_MODEL_CACHE = None

def get_or_load_model() -> Dict[str, Any]:
    global _MODEL_CACHE
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE

    model_path = os.path.join(os.path.dirname(__file__), "models", "phishing_model.joblib")
    if not os.path.exists(model_path):
        from app.ml.train import train_and_export_model
        _MODEL_CACHE = train_and_export_model()
    else:
        try:
            _MODEL_CACHE = joblib.load(model_path)
        except Exception:
            from app.ml.train import train_and_export_model
            _MODEL_CACHE = train_and_export_model()

    return _MODEL_CACHE

FEATURE_EXPLANATIONS = {
    "url_length": "Overall URL character length",
    "domain_length": "Length of the target host domain",
    "dot_count": "Number of dot separators in URL",
    "hyphen_count": "Hyphens used to mimic legitimate names",
    "has_ip_host": "Direct IP address host destination",
    "has_punycode": "Punycode (xn--) internationalized domain encoding",
    "domain_entropy": "Character randomness / DGA indicator",
    "has_suspicious_token": "Presence of high-risk authentication/account keywords",
    "is_https": "HTTPS protocol encryption status",
    "subdomain_count": "Excessive subdomain hierarchy depth"
}

def predict_url_threat(raw_url: str) -> Dict[str, Any]:
    model_data = get_or_load_model()
    clf = model_data["model"]
    scaler = model_data["scaler"]

    features_dict = extract_features_from_url(raw_url)
    vector = np.array([[features_dict[name] for name in FEATURE_NAMES]], dtype=np.float32)
    scaled_vector = scaler.transform(vector)

    proba = float(clf.predict_proba(scaled_vector)[0, 1])
    proba_rounded = round(proba, 4)

    # Classify Risk Level
    if proba_rounded < 0.25:
        classification = "SAFE"
    elif proba_rounded < 0.50:
        classification = "LOW_RISK"
    elif proba_rounded < 0.75:
        classification = "SUSPICIOUS"
    else:
        classification = "HIGH_RISK"

    # Confidence score (distance from decision boundary 0.5)
    confidence = round(float(abs(proba - 0.5) * 2), 3)

    # Feature Importance Attribution
    importances = clf.feature_importances_
    feature_impacts = []
    for name, imp in zip(FEATURE_NAMES, importances):
        val = features_dict[name]
        if imp > 0.03:
            feature_impacts.append({
                "feature": name,
                "impact": round(float(imp), 4),
                "value": val,
                "explanation": FEATURE_EXPLANATIONS.get(name, name)
            })

    feature_impacts.sort(key=lambda x: x["impact"], reverse=True)

    return {
        "probability": proba_rounded,
        "classification": classification,
        "confidenceScore": confidence,
        "modelType": model_data.get("model_type", "RandomForest (Interpretable Ensemble)"),
        "featureImportance": feature_impacts[:5],
        "features": features_dict,
        "notice": "Automated ML predictions evaluate structural and behavioral patterns and may produce false positives. Always verify with full context."
    }
