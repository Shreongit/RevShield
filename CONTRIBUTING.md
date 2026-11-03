<div align="center">

# 🤝 Contributing to RevShield

### Help make the invisible parts of the web visible.

*Free, open-source, transparent web privacy and security intelligence.*

<br>

[Guidelines](#%EF%B8%8F-development-guidelines) • [Setup](#-local-setup) • [Pull Requests](#-submitting-pull-requests) • [Commits](#-commit-style) • [Reporting Issues](#-reporting-issues)

</div>

---

Thank you for your interest in contributing to **RevShield**. Every bug report, tracker signature, test and docs fix helps people understand what websites do behind the scenes.

> 💡 **Philosophy:** every change must keep RevShield *transparent*, *private* and *safe*. If a finding cannot be explained, it does not ship.

---

## 🛠️ Development Guidelines

| | Rule | Details |
|---|---|---|
| 🧱 | **Monorepo structure** | Shared types go in `packages/shared-types`, shared utilities in `packages/shared-utils`, tracker signatures and rule compilation in `packages/rule-engine`. |
| 🛡️ | **Security first** | Never remove or bypass the SSRF checks in `apps/api/app/core/security.py`. PRs that weaken them will be rejected. |
| 🔑 | **No secret leaks** | Never commit secrets, tokens, passwords or test API keys. |
| 🔒 | **Privacy by design** | Never read, store or display cookie values. The extension must never transmit browsing history. |
| 🧠 | **Explainable results** | Every finding and ML phishing factor needs a clear, human-readable reason. |
| ✅ | **Code quality** | Strict TypeScript typing, PEP 8 in Python, and all unit and integration tests passing (`pytest`). |

---

## 🧰 Local Setup

```bash
# Backend
cd apps/api
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend (from the repo root)
npm install
npm run dev:web

# Extension
npm run build:extension
```

Full instructions are in the [README](README.md#-quick-start).

---

## 🌿 Submitting Pull Requests

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/new-tracker-signature
   ```
2. **Implement** your changes with corresponding unit tests.
3. **Verify the build:**
   - Backend: `pytest apps/api/tests/`
   - Frontend: `npm run build`
4. **Commit** with clear, descriptive messages.
5. **Push** to your branch and open a Pull Request describing what changed and why.

### ✔️ PR Checklist

- [ ] Tests added or updated, and `pytest` passes
- [ ] `npm run build` succeeds
- [ ] SSRF protections untouched or strengthened
- [ ] No secrets, tokens or keys committed
- [ ] Shared code placed in the correct `packages/` module
- [ ] Docs updated where behavior changed

---

## 📝 Commit Style

Use short, imperative messages with a type prefix:

```
feat: add tracker signature for session replay vendor
fix: handle protocol downgrade in redirect tracer
docs: clarify extension install steps
test: cover IPv6 loopback in SSRF guard
```

---

## 🐞 Reporting Issues

- Open an issue with steps to reproduce, expected vs. actual behavior, and the URL type involved (without sensitive data).
- **Security vulnerabilities:** do not open a public issue. Report them privately to the maintainer through the contact details on the GitHub profile.

---

## 📄 License

By contributing, you agree that your contributions are licensed under the project's [MIT License](LICENSE).

<div align="center">

<br>

**Thanks for helping keep the web transparent. 🛡️**

</div>
