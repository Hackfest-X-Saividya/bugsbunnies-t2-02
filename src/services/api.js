const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "");

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
    const ruleId = firstString(item.ruleId, item.rule_id);
    const filePath = firstString(item.filePath, item.file_path, item.filename, item.file);
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
    const id = firstString(item.id, item.findingId, item.finding_id) || `${ruleId || "finding"}-${index + 1}`;

    return {
      ...item,
      id,
      ruleId,
      title: firstString(item.title, item.name) || "Title not available",
      severity,
      filePath: filePath || "Not available",
      line,
      lineNumber: line,
      evidence,
      code: evidence,
      description: firstString(item.description, item.explanation),
      owaspCategory: firstString(item.owaspCategory, item.owasp_category),
      mitigation: remediation,
      remediation,
      references: Array.isArray(item.references) ? item.references.filter((reference) => typeof reference === "string") : [],
      endpoint,
      endpointId: firstString(item.endpointId, item.endpoint_id),
      source: firstString(item.source, item.detector),
      confidence: firstString(item.confidence),
      saferAlternative: firstString(item.saferAlternative, item.safer_alternative),
    };
  });
}

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
  const formData = new FormData();
  formData.append("file", file);
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
