
import os
import joblib
import numpy as np

from typing import Any, Dict

from app.ml.feature_extractor import (
    FEATURE_NAMES,
    extract_features_from_url
)

_MODEL_CACHE = None


def get_or_load_model() -> Dict[str, Any]:
    global _MODEL_CACHE

    if _MODEL_CACHE is not None:
        return _MODEL_CACHE

    model_path = os.path.join(
        os.path.dirname(__file__),
        "models",
        "phishing_model.joblib"
    )

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
    "has_punycode": "Punycode internationalized domain encoding",
    "domain_entropy": "Character randomness / DGA indicator",
    "has_suspicious_token": "Presence of high-risk authentication/account keywords",
    "is_https": "HTTPS protocol encryption status",
    "subdomain_count": "Excessive subdomain hierarchy depth"
}


def predict_url_threat(raw_url: str) -> Dict[str, Any]:

    # ==========================================
    # 1. LOAD MODEL
    # ==========================================

    model_data = get_or_load_model()

    clf = model_data["model"]
    scaler = model_data["scaler"]

    # ==========================================
    # 2. EXTRACT URL FEATURES
    # ==========================================

    features_dict = extract_features_from_url(raw_url)

    vector = np.array(
        [[features_dict[name] for name in FEATURE_NAMES]],
        dtype=np.float32
    )

    scaled_vector = scaler.transform(vector)

    # ==========================================
    # 3. PREDICT PHISHING PROBABILITY
    # ==========================================

    probabilities = clf.predict_proba(scaled_vector)[0]

    classes = list(clf.classes_)

    if 1 not in classes:
        raise ValueError(
            "The trained model does not contain "
            "the phishing class (label 1)."
        )

    phishing_index = classes.index(1)

    proba = float(probabilities[phishing_index])

    proba = max(0.0, min(1.0, proba))

    proba_rounded = round(proba, 4)

    # ==========================================
    # 4. CLASSIFICATION
    # ==========================================

    if proba < 0.25:
        classification = "SAFE"

    elif proba < 0.50:
        classification = "LOW_RISK"

    elif proba < 0.75:
        classification = "SUSPICIOUS"

    else:
        classification = "HIGH_RISK"

    # ==========================================
    # 5. MODEL CONFIDENCE
    # ==========================================

    # Maximum predicted class probability.
    # This is NOT calibrated confidence.

    confidence = max(
        float(probabilities[i])
        for i in range(len(probabilities))
    )

    confidence = round(confidence, 3)

    # Decision margin is separate from confidence.
    decision_margin = round(
        abs(proba - 0.5) * 2,
        3
    )

    # ==========================================
    # 6. GLOBAL FEATURE IMPORTANCE
    # ==========================================

    importances = clf.feature_importances_

    feature_impacts = []

    for name, importance in zip(
        FEATURE_NAMES,
        importances
    ):

        value = features_dict[name]

        if importance > 0.03:

            feature_impacts.append({
                "feature": name,
                "impact": round(float(importance), 4),
                "value": value,
                "explanation": FEATURE_EXPLANATIONS.get(
                    name,
                    name
                ),
                "scope": "GLOBAL_MODEL_IMPORTANCE"
            })

    feature_impacts.sort(
        key=lambda item: item["impact"],
        reverse=True
    )

    # ==========================================
    # 7. RESPONSE
    # ==========================================

    return {
        "probability": proba_rounded,

        "classification": classification,

        "confidenceScore": confidence,

        "confidenceMethod": (
            "MAXIMUM_CLASS_PROBABILITY_UNCALIBRATED"
        ),

        "confidenceIsCalibrated": False,

        "decisionMargin": decision_margin,

        "modelType": model_data.get(
            "model_type",
            "RandomForestClassifier (Ensemble)"
        ),

        "featureImportance": feature_impacts[:5],

        "featureImportanceScope": (
            "GLOBAL_MODEL_IMPORTANCE"
        ),

        "featureImportanceNotice": (
            "Feature importance represents global "
            "Random Forest model behaviour. It does not "
            "measure individual feature contributions "
            "to this specific URL prediction."
        ),

        "features": features_dict,

        "notice": (
            "Automated ML predictions evaluate structural "
            "URL patterns and may produce false positives. "
            "Predicted probabilities and confidence values "
            "are not calibrated estimates of real-world risk. "
            "Always verify findings with additional security "
            "evidence and context."
        )
    }
