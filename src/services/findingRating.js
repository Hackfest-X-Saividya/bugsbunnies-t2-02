const KNOWN_SEVERITIES = new Set([
  "Critical",
  "High",
  "Medium",
  "Low",
  "None",
  "Informational",
]);

export function severityFromCvssScore(score) {
  if (
    typeof score !== "number"
    || !Number.isFinite(score)
    || score < 0
    || score > 10
    || !Number.isInteger(score * 10)
  ) {
    return null;
  }
  if (score === 0) return "None";
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

function field(finding, camelCase, snakeCase) {
  return finding[camelCase] ?? finding[snakeCase];
}

export function resolveFindingRating(finding) {
  const rawSeverity = String(finding?.severity ?? "").trim().toLowerCase();
  const informational = rawSeverity === "informational" || rawSeverity === "info";
  if (informational) {
    return {
      severity: "Informational",
      cvssScore: null,
      cvssVector: null,
      scoreNote: "Informational findings are not assigned a CVSS score.",
    };
  }

  const cvssVersion = field(finding ?? {}, "cvssVersion", "cvss_version");
  const cvssScore = field(finding ?? {}, "cvssScore", "cvss_score");
  const cvssVector = field(finding ?? {}, "cvssVector", "cvss_vector");
  const cvssCalculated = field(finding ?? {}, "cvssCalculated", "cvss_calculated");
  const scoredSeverity = severityFromCvssScore(cvssScore);
  if (
    cvssCalculated === true
    && cvssVersion === "4.0"
    && typeof cvssVector === "string"
    && cvssVector.startsWith("CVSS:4.0/")
    && scoredSeverity
  ) {
    return {
      severity: scoredSeverity,
      cvssScore,
      cvssVector,
      scoreNote: "",
    };
  }

  const normalizedSeverity = rawSeverity
    ? `${rawSeverity[0].toUpperCase()}${rawSeverity.slice(1)}`
    : "";
  const severity = KNOWN_SEVERITIES.has(normalizedSeverity)
    ? normalizedSeverity
    : "Unrated";

  return {
    severity,
    cvssScore: null,
    cvssVector: null,
    scoreNote: severity === "Informational"
      ? "Informational findings are not assigned a CVSS score."
      : "CVSS 4.0 score unavailable; no valid backend-calculated CVSS rating was supplied.",
  };
}

export function countFindingsBySeverity(findings) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((severity) => [severity, 0]));
  for (const finding of findings) {
    const severity = resolveFindingRating(finding).severity;
    counts[severity] = (counts[severity] ?? 0) + 1;
  }
  return counts;
}

export const SEVERITY_ORDER = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "None",
  "Informational",
  "Unrated",
];
