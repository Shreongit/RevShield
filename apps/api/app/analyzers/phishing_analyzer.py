from typing import Any, Dict, List
from app.analyzers.base import BaseAnalyzer, AnalysisContext
from app.ml.inference import predict_url_threat

class PhishingAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "phishing_analyzer"

    async def analyze(self, context: AnalysisContext) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []

        # Run ML Inference
        prediction = predict_url_threat(context.normalized_url)

        prob = prediction["probability"]
        classification = prediction["classification"]

        if classification == "HIGH_RISK":
            findings.append({
                "id": "ml-phishing-high",
                "category": "THREAT",
                "title": "High Probability Phishing / Suspicious Pattern",
                "status": "FAIL",
                "impact": "CRITICAL",
                "description": f"Machine learning analysis flagged high-confidence suspicious structural characteristics (Risk Probability: {int(prob * 100)}%).",
                "remediation": "Do not enter credentials or download files from this domain."
            })
        elif classification == "SUSPICIOUS":
            findings.append({
                "id": "ml-phishing-suspicious",
                "category": "THREAT",
                "title": "Moderate Risk Pattern Detected",
                "status": "WARN",
                "impact": "HIGH",
                "description": f"URL exhibits structural indicators common to phishing or spoofing campaigns (Probability: {int(prob * 100)}%).",
                "remediation": "Verify the authenticity of the sender and exact URL spelling."
            })
        elif classification == "LOW_RISK":
            findings.append({
                "id": "ml-phishing-low",
                "category": "THREAT",
                "title": "Low Threat Probability",
                "status": "PASS",
                "impact": "INFO",
                "description": "Model evaluates low probability of malicious intent based on lexical and structural attributes."
            })
        else:
            findings.append({
                "id": "ml-phishing-safe",
                "category": "THREAT",
                "title": "Established Safe Lexical Characteristics",
                "status": "PASS",
                "impact": "INFO",
                "description": "No abnormal entropy, suspicious keywords, or known homograph spoofing indicators detected."
            })

        return {
            "threat": {
                "probability": prob,
                "classification": classification,
                "confidenceScore": prediction["confidenceScore"],
                "modelType": prediction["modelType"],
                "featureImportance": prediction["featureImportance"],
                "indicators": [],
                "notice": prediction["notice"]
            },
            "findings": findings
        }
