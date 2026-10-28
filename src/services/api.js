import {
  checkApiIntelligenceConnection as checkConnection,
  submitApiIntelligenceScan,
} from "./apiIntelligenceIntegration.js";

const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "");

export const isDemoMode = !configuredBaseUrl;

async function request(path, options = {}) {
  if (!configuredBaseUrl) {
    throw new Error("Backend is not configured. Set VITE_API_BASE_URL to use live scans.");
  }
  const response = await fetch(`${configuredBaseUrl}${path}`, {
    ...options,
    headers: {
      ...(options.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...options.headers,
    },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Backend request failed (${response.status}): ${body || response.statusText}`);
  }
  return response.status === 204 ? null : response.json();
}

export function submitScan(file) {
  return submitApiIntelligenceScan(file, { baseUrl: configuredBaseUrl });
}

export function checkBackendConnection() {
  return checkConnection({ baseUrl: configuredBaseUrl });
}

export function getScan(id) {
  return request(`/api/scans/${encodeURIComponent(id)}`);
}

export function getScanFindings(id) {
  return request(`/api/scans/${encodeURIComponent(id)}/findings`);
}

export function getScanRoutes(id) {
  return request(`/api/scans/${encodeURIComponent(id)}/routes`);
}

export function explainFinding(payload) {
  return request("/api/explain", { method: "POST", body: JSON.stringify(payload) });
}

export function getScanReport(id) {
  return request(`/api/scans/${encodeURIComponent(id)}/report`);
}
