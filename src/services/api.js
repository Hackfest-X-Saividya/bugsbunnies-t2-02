const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "");

export const isDemoMode = !configuredBaseUrl;

async function request(path, options = {}) {
  if (!configuredBaseUrl) {
    throw new Error("Backend is not configured. Set VITE_API_BASE_URL to use live scans.");
  }
  let response;
  try {
    response = await fetch(`${configuredBaseUrl}${path}`, {
      ...options,
      headers: {
        ...(options.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
        ...options.headers,
      },
    });
  } catch {
    throw new Error(`Unable to reach the backend at ${configuredBaseUrl}. Start it with "python -m api_intelligence.http_api" and restart Vite after changing .env.`);
  }
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Backend request failed (${response.status}): ${body || response.statusText}`);
  }
  return response.status === 204 ? null : response.json();
}

export function submitScan(files) {
  const formData = new FormData();
  const uploads = Array.isArray(files) ? files : [files];
  for (const file of uploads) {
    const field = uploads.length === 1 && file.name.toLowerCase().endsWith(".zip") ? "file" : "files";
    formData.append(field, file);
  }
  return request("/api/scan", { method: "POST", body: formData });
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
