const configuredBaseUrl = import.meta.env?.VITE_API_BASE_URL?.replace(/\/$/, "");

export const isDemoMode = !configuredBaseUrl;

function firstString(...values) {
  return values.find((value) => typeof value === "string" && value.trim())?.trim() || "";
}

function normalizeEvidence(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.every((line) => typeof line === "string")) return value.join("\n");
  if (value && typeof value === "object") {
    return firstString(value.snippet, value.code, value.text, value.source);
  }
  return "";
}

export function normalizeFindings(items) {
  if (!Array.isArray(items)) throw new Error("The backend findings response must be an array.");
  return items.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`Finding ${index + 1} is not a valid object.`);
    }
    const ruleId = firstString(item.ruleId, item.rule_id, item.test_id);
    const filePath = firstString(item.filePath, item.file_path, item.filename, item.file, item.path);
    const rawLine = item.lineNumber ?? item.line_number ?? item.line;
    const parsedLine = Number(rawLine);
    const line = Number.isInteger(parsedLine) && parsedLine > 0 ? parsedLine : null;
    const rawSeverity = firstString(item.severity);
    const severity = ["high", "medium", "low"].includes(rawSeverity.toLowerCase())
      ? rawSeverity[0].toUpperCase() + rawSeverity.slice(1).toLowerCase()
      : rawSeverity || "Not available";
    const evidence = normalizeEvidence(item.evidence ?? item.code ?? item.snippet);
    const remediation = firstString(item.remediation, item.mitigation, item.suggestedFix, item.suggested_fix);
    const endpoint = firstString(item.endpoint, item.endpointPath, item.endpoint_path);
    const id = firstString(item.id, item.findingId, item.finding_id)
      || `${ruleId || "finding"}-${filePath || "file"}-${line ?? "unknown"}-${index + 1}`;

    return {
      ...item,
      id,
      ruleId,
      title: firstString(item.title, item.name, item.test_name, item.issue_text) || "Title not available",
      severity,
      filePath: filePath || "Not available",
      line,
      lineNumber: line,
      evidence,
      code: evidence,
      description: firstString(item.description, item.explanation, item.issue_text, item.message),
      owaspCategory: firstString(item.owaspCategory, item.owasp_category),
      mitigation: remediation,
      remediation,
      references: Array.isArray(item.references) ? item.references.filter((reference) => typeof reference === "string") : [],
      endpoint,
      endpointId: firstString(item.endpointId, item.endpoint_id),
      source: firstString(item.source, item.detector, item.tool),
      confidence: firstString(item.confidence),
      saferAlternative: firstString(item.saferAlternative, item.safer_alternative),
    };
  });
}

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
  } catch (error) {
    if (error instanceof TypeError) {
      const backend = new URL(configuredBaseUrl).host;
      throw new Error(`Cannot connect to the backend at ${backend}. Make sure it is running and accessible.`);
    }
    throw error;
  }
  if (response.status === 204) return null;

  let body;
  try {
    body = await response.json();
  } catch {
    if (!response.ok) throw new Error(`The backend returned HTTP ${response.status}. The scan was not completed.`);
    throw new Error("Unexpected backend response format. Expected a JSON scan response.");
  }
  if (!response.ok) {
    const kind = body?.error?.kind;
    if (kind === "invalid_zip") throw new Error("The backend rejected the upload because it is not a valid ZIP archive.");
    if (response.status === 413) throw new Error("The ZIP upload exceeds the backend's 20 MiB request limit.");
    if (response.status === 422) throw new Error("The backend could not process this ZIP. It may be invalid or contain unsupported files.");
    if (response.status === 500) throw new Error("The backend could not complete the scan. Check the backend logs or try again later.");
    throw new Error(`The backend returned HTTP ${response.status}. The scan was not completed.`);
  }
  return body;
}

export function normalizeScanResponse(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)
    || payload.status !== "completed"
    || !payload.summary || typeof payload.summary !== "object"
    || !Array.isArray(payload.routes)) {
    throw new Error("Unexpected backend response format. Expected a completed scan with a summary and routes.");
  }

  const rawFindings = [];
  const routeFindingIndexes = [];
  const addFinding = (value, routeIndex = null) => {
    const finding = value?.finding && typeof value.finding === "object" ? value.finding : value;
    if (!finding || typeof finding !== "object" || Array.isArray(finding)) {
      throw new Error("Unexpected backend response format. A finding is not a valid object.");
    }
    const id = firstString(finding.id, finding.finding_id, finding.findingId);
    let findingIndex = id ? rawFindings.findIndex((item) => firstString(item.id, item.finding_id, item.findingId) === id) : -1;
    if (findingIndex === -1) {
      findingIndex = rawFindings.length;
      rawFindings.push(finding);
      routeFindingIndexes.push(new Set());
    }
    if (routeIndex !== null) routeFindingIndexes[findingIndex].add(routeIndex);
  };

  for (const key of ["findings", "security_findings", "unmatched_findings"]) {
    if (payload[key] !== undefined) {
      if (!Array.isArray(payload[key])) throw new Error("Unexpected backend response format. Findings must be an array.");
      payload[key].forEach((finding) => addFinding(finding));
    }
  }
  payload.routes.forEach((route, routeIndex) => {
    if (!route || typeof route !== "object" || Array.isArray(route)) {
      throw new Error(`Unexpected backend response format. Route ${routeIndex + 1} is invalid.`);
    }
    if (route.findings !== undefined) {
      if (!Array.isArray(route.findings)) throw new Error("Unexpected backend response format. Route findings must be an array.");
      route.findings.forEach((finding) => addFinding(finding, routeIndex));
    }
  });

  const findings = normalizeFindings(rawFindings);
  const undocumentedRoutes = new Set(
    Array.isArray(payload.openapi_comparison?.undocumented_routes)
      ? payload.openapi_comparison.undocumented_routes.map((route) => `${route.method} ${route.path}`)
      : [],
  );
  const endpoints = payload.routes.map((route, index) => ({
    ...route,
    id: firstString(route.id) || `live-route-${index + 1}`,
    method: firstString(route.method).toUpperCase() || "UNKNOWN",
    path: firstString(route.path) || "Path not available",
    filePath: firstString(route.filePath, route.file_path, route.file) || "File path not available",
    line: Number.isInteger(route.line) && route.line > 0 ? route.line : null,
    summary: firstString(route.summary, route.handler) || "Discovered Python route",
    documented: payload.openapi_comparison?.available === true
      ? !undocumentedRoutes.has(`${route.method} ${route.path}`)
      : null,
    findings: [],
  }));
  findings.forEach((finding, findingIndex) => {
    let routeIndexes = [...routeFindingIndexes[findingIndex]];
    if (!routeIndexes.length) {
      routeIndexes = endpoints.reduce((matches, endpoint, index) => {
        if (finding.endpointId === endpoint.id
          || finding.endpoint === endpoint.path
          || finding.endpoint === `${endpoint.method} ${endpoint.path}`) matches.push(index);
        return matches;
      }, []);
    }
    const selectedEndpoint = endpoints[routeIndexes[0]];
    if (selectedEndpoint) {
      finding.endpointId = selectedEndpoint.id;
      if (!finding.endpoint) finding.endpoint = `${selectedEndpoint.method} ${selectedEndpoint.path}`;
    }
    routeIndexes.forEach((index) => endpoints[index]?.findings.push(finding.id));
  });

  return {
    id: firstString(payload.id, payload.scan_id) || `live-${Date.now()}`,
    findings,
    endpoints,
    securityFindingsAvailable: payload.summary.security_findings_available === true,
    backendErrors: Array.isArray(payload.errors) ? payload.errors : [],
    limitations: Array.isArray(payload.limitations) ? payload.limitations : [],
  };
}

export async function submitScan(file) {
  const formData = new FormData();
  formData.append("source_zip", file, file.name);
  return normalizeScanResponse(await request("/api/v1/scan", { method: "POST", body: formData }));
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
