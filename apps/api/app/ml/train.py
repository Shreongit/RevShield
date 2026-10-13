import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from app.ml.feature_extractor import FEATURE_NAMES, extract_features_from_url

# Curated training seed URLs
BENIGN_SAMPLES = [
    "https://google.com", "https://wikipedia.org", "https://github.com", "https://mozilla.org",
    "https://apple.com", "https://microsoft.com", "https://amazon.com", "https://cloudflare.com",
    "https://eff.org", "https://stackoverflow.com", "https://nytimes.com", "https://bbc.co.uk",
    "https://reddit.com", "https://python.org", "https://fastapi.tiangolo.com", "https://react.dev",
    "https://vitejs.dev", "https://tailwindcss.com", "https://pypi.org", "https://duckduckgo.com",
    "https://netflix.com", "https://spotify.com", "https://gitlab.com", "https://linkedin.com",
    "https://arxiv.org", "https://nature.com", "https://nih.gov", "https://mit.edu", "https://stanford.edu",
    "https://kernel.org", "https://ubuntu.com", "https://debian.org", "https://archlinux.org",
    "https://w3.org", "https://ietf.org", "https://letsencrypt.org", "https://signal.org", "https://torproject.org"
]

PHISHING_SAMPLES = [
    "http://192.168.1.100/account/login/verify.php",
    "http://secure-paypal-update-account-center.com/login",
    "http://apple-id-verify-billing-suspended.com/auth",
    "http://banking-auth-security-alert-99.top/signin",
    "http://xn--gogl-qqa.com/login.html?redirect=banking",
    "http://netflix-payment-update-center-urgent.click/billing",
    "http://amazon-prime-account-suspended-action.loan/verify",
    "http://verify-wallet-metamask-crypto-sync.top/connect",
    "http://microsoft-365-security-credential-reauth.buzz/login.php",
    "http://10.20.30.40/webscr?cmd=_login-submit",
    "http://chase-bank-online-security-confirmation.tk/signin",
    "http://wellsfargo-identity-verification-portal.ga/login",
    "http://crypto-airdrop-claim-rewards-instant.cf/wallet",
    "http://facebook-security-checkpoint-appeal.gq/login",
    "http://steam-community-free-giftcard-giveaway.top/trade",
    "http://discord-nitro-free-claim-gift-nitro.buzz/login"
]

def generate_augmented_dataset():
    records = []
    labels = []

    # Augment Benign samples with typical subpaths and variations
    for url in BENIGN_SAMPLES:
        feats = extract_features_from_url(url)
        records.append([feats[name] for name in FEATURE_NAMES])
        labels.append(0)

        # Path variations
        for subpath in ["/about", "/contact", "/docs/getting-started", "/blog/2026/04/release", "/products/item?id=123"]:
            v_feats = extract_features_from_url(url + subpath)
            records.append([v_feats[name] for name in FEATURE_NAMES])
            labels.append(0)

    # Augment Phishing samples with synthetic attack vectors
    for url in PHISHING_SAMPLES:
        feats = extract_features_from_url(url)
        records.append([feats[name] for name in FEATURE_NAMES])
        labels.append(1)

        for param in ["?token=xyz998231&session=fake", "?user=target&action=update_card", "?urgent=1&verify=now"]:
            v_feats = extract_features_from_url(url + param)
            records.append([v_feats[name] for name in FEATURE_NAMES])
            labels.append(1)

    return np.array(records), np.array(labels)

def train_and_export_model(output_dir: str = None):
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(output_dir, exist_ok=True)

    X, y = generate_augmented_dataset()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=42,
        class_weight="balanced"
    )
    clf.fit(X_train_scaled, y_train)

    # Predictions
    y_pred = clf.predict(X_test_scaled)
    y_proba = clf.predict_proba(X_test_scaled)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_proba)

    model_payload = {
        "model": clf,
        "scaler": scaler,
        "feature_names": FEATURE_NAMES,
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(auc), 4)
        },
        "model_type": "RandomForestClassifier (Ensemble)"
    }

    model_path = os.path.join(output_dir, "phishing_model.joblib")
    joblib.dump(model_payload, model_path)
    return model_payload

if __name__ == "__main__":
    res = train_and_export_model()
    print(f"Model trained successfully! Metrics: {res['metrics']}")
