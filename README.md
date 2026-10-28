# ShadowGuard AI

Frontend for the BugsBunnies team project at HackFest 2026. ShadowGuard AI connects Python source-code security signals with discovered API endpoints.

## Run locally

```bash
npm install
npm run dev
```

The app starts in **demo mode** when `VITE_API_BASE_URL` is not set. The built-in insecure and secure FastAPI samples load clearly labeled demonstration data. Uploaded archives are not sent anywhere in demo mode.

To enable backend integration, copy `.env.example` to `.env`, set `VITE_API_BASE_URL` to your FastAPI service, and restart Vite. Live scan requests use the centralized service in `src/services/api.js`; failed backend requests are shown as errors rather than replaced with mock results.

## Frontend features

- Responsive landing page and workspace navigation
- Security dashboard with vulnerability and endpoint documentation charts
- ZIP upload validation (50 MB maximum) and sample project demos
- Searchable API explorer and endpoint risk inspection with finding excerpts
- Scan history and workspace integration settings
- Printable report and downloadable PDF export

Finding severity labels retain scanner-provided ratings unless a valid CVSS 4.0
vector is available. The backend calculates CVSS 4.0 scores from the complete
vector, including supported threat and environmental metrics, and the UI derives
severity from the calculated score: Critical (9.0–10.0), High (7.0–8.9),
Medium (4.0–6.9), Low (0.1–3.9), or None (0.0). The current Bandit integration
does not provide CVSS metrics, so its findings retain Bandit's severity labels
and show estimated severity values instead. Estimates are fixed representative
values by label (Critical 9.5, High 8.0, Medium 5.5, Low 2.5, None 0.0); they
are explicitly labeled as estimates and are not CVSS scores. Informational and
unrated findings show "Not rated".

All included scan results and source excerpts are fictional demonstration data. The browser does not execute uploaded source code.
