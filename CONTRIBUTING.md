# Contributing to RevShield

Thank you for your interest in contributing to RevShield! RevShield is a free and open-source project dedicated to transparent web privacy and security intelligence.

---

## 🛠️ Development Guidelines

1. **Monorepo Structure**: Keep shared types in `packages/shared-types` and shared utilities in `packages/shared-utils`.
2. **Security First**: Never remove or bypass SSRF checks in `apps/api/app/core/security.py`.
3. **No Secret Leaks**: Do not commit secrets, tokens, passwords, or test API keys to git.
4. **Code Quality**:
   - Use strict TypeScript typing.
   - Maintain PEP 8 style guidelines in Python modules.
   - Ensure all automated unit and integration tests pass (`pytest`).

---

## 🌿 Submitting Pull Requests

1. Fork the repository and create a feature branch (`git checkout -b feat/new-tracker-signature`).
2. Implement your changes with corresponding unit tests.
3. Verify the build:
   - Backend: `pytest apps/api/tests/`
   - Frontend: `npm run build`
4. Commit your changes with clear, descriptive commit messages.
5. Push to your branch and open a Pull Request.
