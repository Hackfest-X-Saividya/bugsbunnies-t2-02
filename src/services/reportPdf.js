import { jsPDF } from "jspdf";
import { formatFindingRating, resolveFindingRating, SEVERITY_ORDER } from "./findingRating.js";

const PAGE_MARGIN = 18;
const FOOTER_SPACE = 20;
const LINE_HEIGHT = 5;

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "Not provided";
  return String(value);
}

export function createReportPdf(scan, generatedAt = new Date()) {
  const pdf = new jsPDF({ unit: "mm", format: "a4" });
  const pageWidth = pdf.internal.pageSize.getWidth();
  const pageHeight = pdf.internal.pageSize.getHeight();
  const contentWidth = pageWidth - PAGE_MARGIN * 2;
  const findings = scan.findings ?? [];
  const endpoints = scan.endpoints ?? [];
  const severityCounts = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: findings.filter((finding) => resolveFindingRating(finding).severity === severity).length,
  }));
  const affectedEndpoints = new Set(
    findings.map((finding) => finding.endpointId).filter(Boolean),
  ).size;
  let cursorY = PAGE_MARGIN;

  const addPage = () => {
    pdf.addPage();
    cursorY = PAGE_MARGIN;
  };

  const ensureSpace = (height) => {
    if (cursorY + height > pageHeight - FOOTER_SPACE) addPage();
  };

  const addSectionTitle = (title) => {
    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(13);
    const lines = pdf.splitTextToSize(title, contentWidth);
    const titleHeight = lines.length * 6 + 8;
    ensureSpace(titleHeight);
    pdf.setTextColor(15, 23, 42);
    pdf.text(lines, PAGE_MARGIN, cursorY);
    cursorY += titleHeight;
  };

  const addField = (label, value) => {
    const lines = pdf.splitTextToSize(displayValue(value), contentWidth);
    const labelHeight = 4;
    let remainingLines = lines;
    let firstChunk = true;

    while (remainingLines.length) {
      if (cursorY + labelHeight + LINE_HEIGHT > pageHeight - FOOTER_SPACE) addPage();
      pdf.setTextColor(71, 85, 105);
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(8);
      pdf.text(firstChunk ? label : `${label} (continued)`, PAGE_MARGIN, cursorY);
      cursorY += labelHeight;

      const availableLines = Math.max(
        1,
        Math.floor((pageHeight - FOOTER_SPACE - cursorY) / LINE_HEIGHT),
      );
      const chunk = remainingLines.slice(0, availableLines);
      pdf.setTextColor(30, 41, 59);
      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(9);
      pdf.text(chunk, PAGE_MARGIN, cursorY);
      cursorY += chunk.length * LINE_HEIGHT + 3;
      remainingLines = remainingLines.slice(chunk.length);
      firstChunk = false;
      if (remainingLines.length) addPage();
    }
  };

  pdf.setProperties({
    title: `ShadowGuard security report - ${scan.projectName}`,
    subject: "Application security analysis summary",
    creator: "ShadowGuard AI",
  });
  pdf.setFillColor(15, 23, 42);
  pdf.rect(0, 0, pageWidth, 42, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(10);
  pdf.text(scan.isDemo ? "DEMONSTRATION REPORT" : "SCAN REPORT", PAGE_MARGIN, 15);
  pdf.setFontSize(21);
  pdf.text(pdf.splitTextToSize(displayValue(scan.projectName), contentWidth), PAGE_MARGIN, 25);
  pdf.setFont("helvetica", "normal");
  pdf.setFontSize(9);
  pdf.text(
    `Scan ${displayValue(scan.id)}  |  Status ${displayValue(scan.status)}  |  Generated ${new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(generatedAt)}`,
    PAGE_MARGIN,
    35,
  );
  cursorY = 53;

  addSectionTitle("Application security analysis summary");
  addField("TOTAL FINDINGS", `${findings.length} potential scanner findings`);
  severityCounts.forEach(({ severity, count }) => addField(`${severity.toUpperCase()} FINDINGS`, count));
  addField(
    "AFFECTED ENDPOINTS",
    `${affectedEndpoints} of ${endpoints.length} discovered routes`,
  );
  addField(
    "ASSESSMENT DISCLAIMER",
    "Scanner output identifies potential risks, not confirmed vulnerabilities. Validate findings with the complete source and deployment context.",
  );
  if (scan.securityFindingsAvailable === false) {
    addField(
      "SCANNER COVERAGE",
      "This API Intelligence endpoint performs route discovery only. Security findings were not assessed; an empty findings list does not mean the project is secure.",
    );
  }
  addSectionTitle(`Detailed findings (${findings.length})`);

  if (findings.length === 0) {
    addField(
      "RESULT",
      scan.securityFindingsAvailable === false
        ? "Security findings were not assessed by this API Intelligence endpoint."
        : "No scanner findings are included in this scan.",
    );
  } else {
    const fields = [
      ["ID", "id"],
      ["Title", "title"],
      ["Severity rating", null],
      ["CVSS 4.0 vector", null],
      ["Status", "status"],
      ["File", "filePath"],
      ["Line", "line"],
      ["Endpoint", "endpoint"],
      ["Description", "description"],
      ["Evidence", "evidence"],
      ["Impact", "impact"],
      ["Confidence", "confidence"],
      ["Mitigation", "mitigation"],
      ["Detection source", "source"],
    ];

    findings.forEach((finding, index) => {
      const rating = resolveFindingRating(finding);
      addSectionTitle(`Finding ${index + 1}: ${displayValue(finding.title)}`);
      fields.forEach(([label, key]) => {
        if (label === "Severity rating") {
          addField(label, formatFindingRating(rating));
        } else if (label === "CVSS 4.0 vector") {
          addField(label, rating.cvssVector);
        } else {
          const value = key === "filePath"
            ? finding.filePath ?? finding.file_path
            : key === "line"
              ? finding.line ?? finding.line_number
              : key === "mitigation"
              ? finding.mitigation ?? finding.remediation
              : key === "evidence"
                ? finding.evidence ?? finding.code
                : key === "impact"
                  ? finding.impact ?? finding.description
                : finding[key];
          addField(label, value);
        }
      });
      cursorY += 3;
    });
  }

  const pageCount = pdf.internal.getNumberOfPages();
  for (let page = 1; page <= pageCount; page += 1) {
    pdf.setPage(page);
    pdf.setDrawColor(203, 213, 225);
    pdf.line(PAGE_MARGIN, pageHeight - 14, pageWidth - PAGE_MARGIN, pageHeight - 14);
    pdf.setTextColor(100, 116, 139);
    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(8);
    pdf.text("ShadowGuard AI · Security report", PAGE_MARGIN, pageHeight - 9);
    pdf.text(`Page ${page} of ${pageCount}`, pageWidth - PAGE_MARGIN, pageHeight - 9, {
      align: "right",
    });
  }

  return pdf.output("arraybuffer");
}
