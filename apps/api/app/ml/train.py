
import os
import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from app.ml.feature_extractor import (
    FEATURE_NAMES,
    extract_features_from_url
)


# ==========================================
# CURATED TRAINING SEED URLS
# ==========================================

BENIGN_SAMPLES = [
    "https://google.com", "https://wikipedia.org",
    "https://github.com", "https://mozilla.org",
    "https://apple.com", "https://microsoft.com",
    "https://amazon.com", "https://cloudflare.com",
    "https://eff.org", "https://stackoverflow.com",
    "https://nytimes.com", "https://bbc.co.uk",
    "https://reddit.com", "https://python.org",
    "https://fastapi.tiangolo.com", "https://react.dev",
    "https://vitejs.dev", "https://tailwindcss.com",
    "https://pypi.org", "https://duckduckgo.com",
    "https://netflix.com", "https://spotify.com",
    "https://gitlab.com", "https://linkedin.com",
    "https://arxiv.org", "https://nature.com",
    "https://nih.gov", "https://mit.edu",
    "https://stanford.edu", "https://kernel.org",
    "https://ubuntu.com", "https://debian.org",
    "https://archlinux.org", "https://w3.org",
    "https://ietf.org", "https://letsencrypt.org",
    "https://signal.org", "https://torproject.org"
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


# ==========================================
# DATASET GENERATION
# ==========================================

def generate_augmented_dataset(return_groups=False):

    records = []
    labels = []
    groups = []

    benign_paths = [
        "/about",
        "/contact",
        "/docs/getting-started",
        "/blog/2026/04/release",
        "/products/item?id=123"
    ]

    phishing_params = [
        "?token=xyz998231&session=fake",
        "?user=target&action=update_card",
        "?urgent=1&verify=now"
    ]

    # --------------------------------------
    # BENIGN URL AUGMENTATION
    # --------------------------------------

    for index, url in enumerate(BENIGN_SAMPLES):

        group_id = f"benign_{index}"

        variants = [url]

        variants.extend(
            url + path for path in benign_paths
        )

        for variant in variants:

            features = extract_features_from_url(variant)

            records.append([
                features[name] for name in FEATURE_NAMES
            ])

            labels.append(0)
            groups.append(group_id)

    # --------------------------------------
    # PHISHING URL AUGMENTATION
    # --------------------------------------

    for index, url in enumerate(PHISHING_SAMPLES):

        group_id = f"phishing_{index}"

        variants = [url]

        variants.extend(
            url + param for param in phishing_params
        )

        for variant in variants:

            features = extract_features_from_url(variant)

            records.append([
                features[name] for name in FEATURE_NAMES
            ])

            labels.append(1)
            groups.append(group_id)

    X = np.asarray(records, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int32)
    groups = np.asarray(groups)

    if return_groups:
        return X, y, groups

    return X, y


# ==========================================
# MODEL TRAINING
# ==========================================

def train_and_export_model(output_dir=None):

    if output_dir is None:
        output_dir = os.path.join(
            os.path.dirname(__file__),
            "models"
        )

    os.makedirs(output_dir, exist_ok=True)

    X, y, groups = generate_augmented_dataset(
        return_groups=True
    )

    # --------------------------------------
    # GROUP-AWARE TRAIN / TEST SPLIT
    # --------------------------------------

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=42
    )

    train_indices, test_indices = next(
        splitter.split(X, y, groups)
    )

    X_train = X[train_indices]
    X_test = X[test_indices]

    y_train = y[train_indices]
    y_test = y[test_indices]

    train_groups = set(groups[train_indices])
    test_groups = set(groups[test_indices])

    # Explicit leakage protection
    if train_groups.intersection(test_groups):
        raise RuntimeError(
            "Data leakage detected: seed URL groups "
            "appear in both training and testing sets."
        )

    if len(np.unique(y_train)) < 2:
        raise RuntimeError(
            "Training split must contain both classes."
        )

    if len(np.unique(y_test)) < 2:
        raise RuntimeError(
            "Testing split must contain both classes. "
            "Review the group split configuration."
        )

    # --------------------------------------
    # FEATURE SCALING
    # --------------------------------------

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(X_train)

    X_test_scaled = scaler.transform(X_test)

    # --------------------------------------
    # RANDOM FOREST MODEL
    # --------------------------------------

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=42,
        class_weight="balanced"
    )

    clf.fit(X_train_scaled, y_train)

    # --------------------------------------
    # MODEL EVALUATION
    # --------------------------------------

    y_pred = clf.predict(X_test_scaled)

    phishing_index = list(clf.classes_).index(1)

    y_proba = clf.predict_proba(
        X_test_scaled
    )[:, phishing_index]

    acc = accuracy_score(y_test, y_pred)

    prec = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    rec = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    auc = roc_auc_score(y_test, y_proba)

    metrics = {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": round(float(auc), 4)
    }

    # --------------------------------------
    # MODEL METADATA
    # --------------------------------------

    model_payload = {
        "model": clf,
        "scaler": scaler,
        "feature_names": FEATURE_NAMES,

        "metrics": metrics,

        "evaluation": {
            "method": "GroupShuffleSplit",
            "test_size": 0.20,
            "random_state": 42,
            "training_samples": int(len(train_indices)),
            "testing_samples": int(len(test_indices)),
            "training_seed_groups": int(len(train_groups)),
            "testing_seed_groups": int(len(test_groups)),
            "group_overlap": False,
            "leakage_check": "PASSED"
        },

        "dataset": {
            "benign_seed_urls": len(BENIGN_SAMPLES),
            "phishing_seed_urls": len(PHISHING_SAMPLES),
            "total_seed_urls": (
                len(BENIGN_SAMPLES)
                + len(PHISHING_SAMPLES)
            ),
            "synthetic_augmentation": True
        },

        "model_type": "RandomForestClassifier (Ensemble)"
    }

    # --------------------------------------
    # EXPORT MODEL
    # --------------------------------------

    model_path = os.path.join(
        output_dir,
        "phishing_model.joblib"
    )

    joblib.dump(model_payload, model_path)

    return model_payload


# ==========================================
# EXECUTION
# ==========================================

if __name__ == "__main__":

    result = train_and_export_model()

    print("\nModel trained successfully!")

    print("\nEvaluation Metrics:")

    for name, value in result["metrics"].items():
        print(f"{name}: {value}")

    print("\nEvaluation Method:")
    print(result["evaluation"])

    print("\nDataset Information:")
    print(result["dataset"])
