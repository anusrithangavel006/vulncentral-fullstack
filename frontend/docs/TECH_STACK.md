# Technology Stack and Verification

## 1. Technologies actually used in this build
| Layer | Technology | Where / how it is used |
|---|---|---|
| Markup | HTML5 | `index.html` shell; pages rendered into `<main>` |
| Styling | CSS3 | Custom properties (design tokens), Flexbox, CSS Grid, media queries (responsive), `prefers-color-scheme` (dark mode), print styles |
| Logic | JavaScript (ES2020 modules) | State object, page render functions, event delegation, filtering, sorting, pagination |
| Charts | Inline SVG (hand-written) | Donut, line and stacked bar charts driven by the sample data |
| Tooling | Vite 5 | Dev server (`npm run dev`) and production bundler (`npm run build`) |
| Runtime/tools | Node.js, npm, VS Code, Git | Development and version control |
| Browser APIs | Blob / URL.createObjectURL, window.print | CSV export and print-friendly report |

Note: this frontend does **not** use React, Recharts or any backend. Do not list them as implemented.

## 2. Planned for later stages (not implemented)
| Layer | Planned technology |
|---|---|
| UI framework | React (component split of the current pages) with Recharts |
| Backend API | Node.js/Express or Python/FastAPI |
| Database | PostgreSQL (vulnerability registry, assets, tasks) |
| Data sources | NVD API, CISA KEV catalog, vendor advisories |
| AI | LLM API for explanations and query answering |
| Cloud | Container deployment on a cloud provider, scheduled collectors |
| Security | Authentication/authorization and role-based access |

## 3. Requirement checklist (what to demonstrate)
- [x] Sidebar with all 10 pages; opens directly on Overview (no login)
- [x] Overview: 6 clickable cards, donut, trend line, asset-risk bar chart, alerts table with detail view, priority actions, data-source status
- [x] Registry: search, severity/source/exploit/date filters, sortable columns, pagination, detail panel with 8 explanation sections
- [x] AI Assistant: chat, suggested questions, session history, 6-part structured answers, rule-based and labelled as such
- [x] Assets: search, type filter, detail drawer, match categories, register-asset form, refresh action
- [x] Threat Intelligence: recent, exploited, vendor advisories, fixes available
- [x] Event Monitor: simulated events with investigation steps, clearly not confirmed incidents
- [x] Risk Analysis: transparent rules and inputs per row; exposure shown as Unknown
- [x] Remediation: status dropdowns, progress bar, overdue list
- [x] Reports: date filters, preview, CSV export, print
- [x] About: problem, aim, solution, modules, data flow, limitations, future work

## 4. Manual test steps (for the demonstration)
1. Click each sidebar item; every page loads.
2. Registry: type `log4j`; filter Critical; sort CVSS; go to page 2; click a row.
3. Assistant: click each suggested question.
4. Assets: register a new asset, open its drawer, press Refresh.
5. Remediation: change a task to Resolved and check the progress bar and overdue list.
6. Reports: set a date range, export CSV, press Print.
7. Resize the window to phone width and confirm the layout adapts.

## 5. Honest limitations
Sample data only; rule-based assistant; no live NVD/CISA integration; no real monitoring; this is not antivirus, penetration testing or EDR.
