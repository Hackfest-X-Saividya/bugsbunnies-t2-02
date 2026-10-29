export const SCAN_HISTORY_STORAGE_KEY = "shadowguard.scan-history.v1";

const STORAGE_VERSION = 1;

const findingFields = [
  "id", "ruleId", "rule_id", "test_id", "title", "severity", "filePath",
  "file_path", "line", "lineNumber", "line_number", "description",
  "owaspCategory", "owasp_category", "mitigation", "remediation",
  "references", "endpoint", "endpointId", "source", "confidence",
  "saferAlternative", "cvssVersion", "cvss_version", "cvssScore",
  "cvss_score", "cvssVector", "cvss_vector", "cvssCalculated",
  "cvss_calculated", "status", "impact",
];

const endpointFields = [
  "id", "method", "path", "handler", "file", "filePath", "file_path",
  "line", "summary", "documented", "security_signals", "securitySignals",
];

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function pickFields(value, fields) {
  return Object.fromEntries(fields
    .filter((field) => value[field] !== undefined)
    .map((field) => [field, value[field]]));
}

function persistableScan(scan) {
  return {
    id: scan.id,
    projectName: scan.projectName,
    status: scan.status,
    completedAt: scan.completedAt,
    isDemo: false,
    securityFindingsAvailable: scan.securityFindingsAvailable === true,
    findings: scan.findings.map((finding) => pickFields(finding, findingFields)),
    endpoints: scan.endpoints.map((endpoint) => ({
      ...pickFields(endpoint, endpointFields),
      findings: Array.isArray(endpoint.findings)
        ? endpoint.findings.filter((findingId) => typeof findingId === "string")
        : [],
    })),
    backendErrors: Array.isArray(scan.backendErrors)
      ? scan.backendErrors.map((error) => pickFields(error, ["code", "message", "stage"]))
      : [],
    limitations: Array.isArray(scan.limitations) ? scan.limitations : [],
  };
}

function isLiveScan(scan) {
  return isRecord(scan)
    && typeof scan.id === "string"
    && scan.id.length > 0
    && scan.isDemo !== true
    && Array.isArray(scan.findings)
    && Array.isArray(scan.endpoints);
}

function getStorage(storage) {
  if (storage !== undefined) return storage;
  try {
    return globalThis.localStorage;
  } catch {
    return null;
  }
}

export function createScanHistoryState(scans = [], selectedScanId = null) {
  const liveScans = scans.filter(isLiveScan);
  const selected = liveScans.some((scan) => scan.id === selectedScanId)
    ? selectedScanId
    : liveScans[0]?.id ?? null;
  return { scans: liveScans, selectedScanId: selected };
}

export function addLiveScan(state, scan) {
  if (!isLiveScan(scan)) return state;
  return createScanHistoryState(
    [scan, ...state.scans.filter((existing) => existing.id !== scan.id)],
    scan.id,
  );
}

export function selectLiveScan(state, scanId) {
  if (!state.scans.some((scan) => scan.id === scanId)) return state;
  return { ...state, selectedScanId: scanId };
}

export function readScanHistory(storage) {
  const target = getStorage(storage);
  if (!target) {
    return {
      ...createScanHistoryState(),
      error: "Scan history storage is unavailable; scans will remain available until this tab closes.",
    };
  }

  try {
    const serialized = target.getItem(SCAN_HISTORY_STORAGE_KEY);
    if (!serialized) return { ...createScanHistoryState(), error: "" };
    const stored = JSON.parse(serialized);
    if (!isRecord(stored) || stored.version !== STORAGE_VERSION || !Array.isArray(stored.scans)) {
      return {
        ...createScanHistoryState(),
        error: "Saved scan history has an unsupported format and could not be loaded.",
      };
    }

    return {
      ...createScanHistoryState(stored.scans, stored.selectedScanId),
      error: "",
    };
  } catch {
    return {
      ...createScanHistoryState(),
      error: "Saved scan history could not be read; scans will remain available until this tab closes.",
    };
  }
}

export function writeScanHistory(storage, state) {
  const target = getStorage(storage);
  if (!target) return "Scan history could not be saved because browser storage is unavailable.";

  try {
    const stored = createScanHistoryState(state.scans, state.selectedScanId);
    target.setItem(SCAN_HISTORY_STORAGE_KEY, JSON.stringify({
      version: STORAGE_VERSION,
      selectedScanId: stored.selectedScanId,
      scans: stored.scans.map(persistableScan),
    }));
    return "";
  } catch {
    return "Scan history could not be saved. Check browser storage availability and try again.";
  }
}
