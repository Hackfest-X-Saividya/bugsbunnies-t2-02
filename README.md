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
- Printable report and downloadable CSV export

All included scan results and source excerpts are fictional demonstration data. The browser does not execute uploaded source code.
