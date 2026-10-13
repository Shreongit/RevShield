# REVSHIELD — Project Overview Website

This directory (`/Webpage`) contains an independent, static project presentation and documentation website for **REVSHIELD**.

---

## 🌟 Purpose

This website serves as a public-facing informational overview for:
- GitHub Pages hosting
- Portfolios & Hackathons
- Open-source presentations and developer documentation
- Explaining the multi-vector security & privacy analysis architecture, browser extension, and local-first principles.

> **Note**: This website is completely independent and static. It does not modify, depend upon, or interfere with the main REVSHIELD application in `apps/` or `packages/`.

---

## 📁 File Structure

```text
Webpage/
├── index.html          # Semantic HTML5 single-page overview site
├── styles/
│   └── main.css        # Responsive stylesheet with Light & Dark mode tokens
├── scripts/
│   └── main.js         # Theme toggle, interactive extension demo, & copy scripts
├── assets/
│   └── logo.svg        # REVSHIELD shield SVG logo
└── README.md           # This documentation
```

---

## 🚀 How to Run Locally

Because the website is purely static HTML, CSS, and Vanilla JavaScript, you can run it with any static web server:

### Option 1: Python Built-in Server (Easiest)
From the `/Webpage` folder:
```bash
cd Webpage
python -m http.server 3000
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser.

### Option 2: Node.js `npx serve`
```bash
npx serve Webpage
```

### Option 3: Direct File Opening
You can also directly double-click `Webpage/index.html` to open it in any modern browser.

---

## 🌐 How to Deploy to GitHub Pages

### Method 1: Deploy Directly from Branch / Subdirectory
1. Go to your repository settings on GitHub: `Settings` &rarr; `Pages`.
2. Under **Build and deployment**:
   - Source: **Deploy from a branch**.
   - If using a dedicated `gh-pages` branch, you can push the contents of `/Webpage` to `gh-pages`.

### Method 2: GitHub Actions Workflow (`.github/workflows/pages.yml`)
To automatically publish `/Webpage` to GitHub Pages upon pushing to `main`:

```yaml
name: Deploy Webpage to GitHub Pages

on:
  push:
    branches:
      - main
    paths:
      - 'Webpage/**'

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: 'pages'
  cancel-in-progress: false

jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Pages
        uses: actions/configure-pages@v4

      - name: Upload Artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: 'Webpage'

      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

---

## 🎨 Features & Design

- **Light & Dark Mode**: Persistent theme toggle with automatic system preference detection.
- **Interactive Extension Demo**: Test the toggle switch to see real-time status and counter transitions.
- **Responsive System Architecture**: Multi-tier architecture diagram adaptable for desktop and mobile screens.
- **Copyable Setup Blocks**: 1-click copy buttons for cloning and running REVSHIELD locally.
- **Zero External Runtime Dependencies**: Blazing-fast load times with pure CSS and Vanilla JS.
