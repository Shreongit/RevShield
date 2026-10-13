# RevShield

> **Understand what happens behind every website.**  
> Free, transparent, and open-source website security, privacy, tracker, cookie, and threat intelligence analysis platform with continuous local browser protection.
---

## 🌟 Overview

RevShield provides comprehensive visibility into how websites handle your security and privacy. Enter any URL to immediately audit:
- **Transport Security & TLS**: Certificate chain validity, expiration, protocol version, cipher suites.
- **Security Headers**: In-depth audit of Content-Security-Policy (CSP), HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy with educational explanations and impact ratings.
- **Privacy & Trackers**: Identifies tracking scripts, advertising networks, session replay tools, and canvas fingerprinting vectors.
- **Cookie & Storage Vectors**: First-party vs. third-party cookie distinction, `Secure` / `HttpOnly` / `SameSite` compliance without exposing sensitive values.
- **Redirect Tracing**: Multi-hop HTTP status and protocol downgrade detection.
- **Machine Learning Threat Detection**: Interpretable lexical and structural phishing classification with transparent factor attribution.
- **Continuous Local Extension**: Manifest V3 browser extension that blocks trackers and ads locally using native DeclarativeNetRequest rules without transmitting browsing history.
- **100% Free & No Account Required**: Completely open for everyone without any sign-up walls.

---

## 🏗️ Architecture

```
RevShield/
├── apps/
│   ├── web/               # React + TypeScript + Vite + Tailwind CSS frontend
│   ├── api/               # FastAPI + SQLAlchemy + Celery + Scikit-Learn backend
│   └── extension/         # Manifest V3 browser extension with DeclarativeNetRequest
├── packages/
│   ├── shared-types/      # TypeScript interfaces shared between web and extension
│   ├── shared-utils/      # URL normalization, risk tiering, entropy calculation
│   └── rule-engine/       # Tracker signatures and DeclarativeNetRequest rule compiler
└── docker/                # Multi-container Docker Compose configuration
```

---

## 🚀 Quick Start (Local Development)

### Prerequisites
- Node.js 18+ and npm
- Python 3.10+
- (Optional) Docker and Docker Compose

### 1. Backend API & Analysis Engine
```bash
# Navigate to API
cd apps/api

# Install dependencies
pip install -r requirements.txt

# Run FastAPI backend
uvicorn app.main:app --reload --port 8000
```
API Documentation available at: `http://localhost:8000/docs`

### 2. Frontend Web Application
```bash
# Install workspace dependencies
npm install

# Start development server
npm run dev:web
```
Web Application available at: `http://localhost:5173`

### 3. Build Browser Extension
```bash
# Build extension bundle
npm run build:extension
```
Load the unpacked extension in Chrome / Brave / Edge / Arc:
1. Navigate to `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** and select `apps/extension/dist`

---

## 🐳 Docker Deployment

To launch the full stack (PostgreSQL, Redis, API, and Web):
```bash
docker-compose up --build
```

---

## 🛡️ Anti-SSRF and Security Design

RevShield inspects arbitrary user-supplied URLs safely:
1. **Scheme Whitelist**: Strictly allows `http://` and `https://` only.
2. **DNS & IP Validation**: Resolves DNS before request dispatch and blocks IPv4/IPv6 loopbacks (`127.0.0.0/8`, `::1`), private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud metadata (`169.254.169.254`), multicast, and internal hostnames.
3. **Execution Limits**: Capped response stream size (5MB), 8-second connect/read timeouts, and maximum 5 redirects.

---

## 🧪 Testing

Run backend tests:
```bash
cd apps/api
pytest
```

---

## 📄 License

RevShield is released under the [MIT License](LICENSE).
