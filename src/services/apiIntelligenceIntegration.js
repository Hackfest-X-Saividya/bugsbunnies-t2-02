function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function mapRoute(route, undocumentedPaths, index) {
  if (
    !isRecord(route)
    || typeof route.method !== "string"
    || typeof route.path !== "string"
    || typeof route.handler !== "string"
    || typeof route.file !== "string"
    || !Number.isInteger(route.line)
    || !Array.isArray(route.findings)
    || !Array.isArray(route.security_signals)
  ) {
    throw new Error("The backend returned a route with an unsupported shape.");
  }

  const isDocumented = undocumentedPaths === null
    ? null
    : !undocumentedPaths.has(`${route.method.toUpperCase()} ${route.path}`);

  return {
    id: `route-${index + 1}`,
    method: route.method,
    path: route.path,
    documented: isDocumented,
    filePath: route.file,
    line: route.line,
    summary: route.handler,
    parameters: [...route.path.matchAll(/\{([^{}]+)\}/g)]
      .map(([, parameter]) => `${parameter} · path · required`),
    findings: [],
    securitySignals: route.security_signals,
    handlerRange: route.handler_range,
  };
}

export function adaptApiIntelligenceResponse(response, projectName, id = `api-intelligence-${Date.now()}`) {
  if (
    !isRecord(response)
    || response.status !== "completed"
    || !isRecord(response.summary)
    || response.summary.security_findings_available !== false
    || !Number.isInteger(response.summary.routes_discovered)
    || !Array.isArray(response.routes)
    || response.summary.routes_discovered !== response.routes.length
    || !Array.isArray(response.unmatched_findings)
    || response.unmatched_findings.length !== 0
    || !Array.isArray(response.errors)
    || !Array.isArray(response.limitations)
  ) {
    throw new Error("The backend response is not a completed API Intelligence scan.");
  }

  const comparison = response.openapi_comparison;
  let undocumentedPaths = null;
  if (comparison !== null) {
    if (
      !isRecord(comparison)
      || typeof comparison.available !== "boolean"
      || !Array.isArray(comparison.undocumented_routes)
      || !Array.isArray(comparison.documented_operations_not_found)
    ) {
      throw new Error("The backend returned an unsupported OpenAPI comparison.");
    }
    if (comparison.available) {
      undocumentedPaths = new Set(
        comparison.undocumented_routes.map(({ method, path }) => {
          if (typeof method !== "string" || typeof path !== "string") {
            throw new Error("The backend returned an invalid OpenAPI route comparison.");
          }
          return `${method.toUpperCase()} ${path}`;
        }),
      );
    }
  }

  return {
    id,
    projectName,
    status: "Complete",
    findings: [],
    endpoints: response.routes.map((route, index) => {
      if (Array.isArray(route?.findings) && route.findings.length > 0) {
        throw new Error("The backend returned security findings that this integration cannot represent.");
      }
      return mapRoute(route, undocumentedPaths, index);
    }),
    isDemo: false,
    securityFindingsAvailable: false,
    scanErrors: response.errors,
    scanLimitations: response.limitations,
  };
}

export async function submitApiIntelligenceScan(file, { baseUrl, fetchImpl = globalThis.fetch } = {}) {
  if (typeof baseUrl !== "string" || !baseUrl.trim()) {
    throw new Error("Backend is not configured. Set VITE_API_BASE_URL to use live scans.");
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("Fetch is unavailable; cannot connect to the configured backend.");
  }

  const formData = new FormData();
  formData.append("source_zip", file, file.name);
  const response = await fetchImpl(`${baseUrl.replace(/\/$/, "")}/api/v1/scan`, {
    method: "POST",
    body: formData,
  });
  const responseText = await response.text();
  let body;
  try {
    body = responseText ? JSON.parse(responseText) : null;
  } catch {
    throw new Error(`Backend returned invalid JSON (${response.status}).`);
  }

  if (!response.ok) {
    const message = body?.error?.message;
    throw new Error(
      typeof message === "string" && message
        ? `Backend request failed (${response.status}): ${message}`
        : `Backend request failed (${response.status}): ${response.statusText || "Unknown error"}`,
    );
  }
  if (!isRecord(body)) {
    throw new Error("Backend returned an empty or invalid scan response.");
  }
  return body;
}

export async function checkApiIntelligenceConnection({
  baseUrl,
  fetchImpl = globalThis.fetch,
} = {}) {
  if (typeof baseUrl !== "string" || !baseUrl.trim()) {
    throw new Error("Backend is not configured. Set VITE_API_BASE_URL to use live scans.");
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("Fetch is unavailable; cannot connect to the configured backend.");
  }

  const response = await fetchImpl(`${baseUrl.replace(/\/$/, "")}/api/v1/scan`, {
    method: "OPTIONS",
  });
  if (!response.ok) {
    throw new Error(`Backend connection check failed (${response.status}).`);
  }

  const responseText = await response.text();
  let body;
  try {
    body = responseText ? JSON.parse(responseText) : null;
  } catch {
    throw new Error(`Backend returned invalid connection-check JSON (${response.status}).`);
  }
  if (!isRecord(body) || body.status !== "ok") {
    throw new Error("The configured server did not identify itself as the API Intelligence backend.");
  }
  return true;
}
