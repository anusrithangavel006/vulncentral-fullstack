# VulnCentral Intelligence

Cloud-Native Centralized Vulnerability Registry and Intelligent Security Query Interface for Institutions — **frontend stage**.

## Run
```bash
npm install
npm run dev        # http://localhost:5173
npm run build      # production build in dist/
npm run preview    # serve the production build
```
Requires Node.js 18+.

## What this is (and is not)
A frontend that demonstrates how an institution can centralize known vulnerability information, match it to assets, prioritize remediation and query it in plain language. All data is a **local sample dataset** (`src/main.js`). The assistant is **rule-based**; no LLM, live feed, scanner or backend is connected. No authentication is implemented, by design.

## Pages
Overview · Vulnerability Registry · AI Security Assistant · Institutional Assets · Threat Intelligence · Security Event Monitor · Risk Analysis · Remediation Center · Reports & Analytics · About Project

## Structure
```
index.html        page shell
src/main.js       sample data, state, page renderers, event handling
src/style.css     design tokens, layout, responsive + dark mode + print styles
docs/TECH_STACK.md   technologies used, requirement checklist, test steps
```
