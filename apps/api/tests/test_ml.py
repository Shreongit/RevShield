import pytest
from app.ml.feature_extractor import extract_features_from_url
from app.ml.inference import predict_url_threat

def test_feature_extraction():
    feats = extract_features_from_url("https://secure-login.bank.top/auth/verify?token=123")
    assert feats["is_https"] == 1
    assert feats["has_suspicious_token"] == 1
    assert feats["subdomain_count"] >= 1
    assert feats["url_length"] > 20

def test_ml_prediction():
    res_safe = predict_url_threat("https://wikipedia.org")
    assert res_safe["classification"] in ("SAFE", "LOW_RISK")
    assert "probability" in res_safe
    assert "featureImportance" in res_safe

    res_phish = predict_url_threat("http://secure-paypal-update-account-center.com/login?token=urgent")
    assert res_phish["probability"] > res_safe["probability"]
