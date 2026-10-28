import assert from "node:assert/strict";
import test from "node:test";
import { createReportPdf } from "../src/services/reportPdf.js";

test("creates a valid PDF report with the complete finding documentation", () => {
  const scan = {
    id: "scan-123",
    projectName: "billing-api",
    status: "Completed",
    isDemo: false,
    endpoints: [{ id: "endpoint-1" }],
    findings: [
      {
        id: "SG-2001",
        title: "Unsafe query",
        severity: "High",
        status: "Potential",
        filePath: "src/users.py",
        line: 42,
        endpoint: "GET /users/{id}",
        description: "User input is inserted into a query.",
        mitigation: "Use a parameterized query.",
        source: "Static scanner",
        evidence: 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        confidence: "Medium",
      },
    ],
  };
  const pdf = Buffer.from(createReportPdf(scan, new Date("2026-10-28T00:00:00Z")));
  const content = pdf.toString("latin1");

  assert.equal(content.startsWith("%PDF-"), true);
  assert.match(content, /%%EOF\s*$/);
  for (const value of [
    "billing-api",
    "SG-2001",
    "Unsafe query",
    "High",
    "Potential",
    "src/users.py",
    "42",
    "GET /users/{id}",
    "User input is inserted into a query.",
    "Use a parameterized query.",
    "Static scanner",
    "High \\(Estimated: 8.0\\)",
    "Evidence",
    "Medium",
  ]) {
    assert.ok(content.includes(value), `PDF should contain ${value}`);
  }
});

test("shows informational findings without inventing CVSS ratings", () => {
  const pdf = Buffer.from(createReportPdf({
    id: "rated-scan",
    projectName: "rated-project",
    status: "Completed",
    findings: [{
      id: "INFO-1",
      title: "Informational route note",
      severity: "Informational",
    }],
    endpoints: [],
  })).toString("latin1");

  assert.ok(pdf.includes("Informational \\(Not rated\\)"));
  assert.ok(pdf.includes("INFORMATIONAL FINDINGS"));
});

test("includes backend-calculated CVSS score and matching severity in the PDF", () => {
  const content = Buffer.from(createReportPdf({
    id: "cvss-scan",
    projectName: "cvss-project",
    status: "Completed",
    findings: [{
      id: "CVSS-1",
      title: "Validated vector",
      severity: "critical",
      cvss_version: "4.0",
      cvss_score: 9.9,
      cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
      cvss_calculated: true,
    }],
    endpoints: [],
  })).toString("latin1");

  assert.ok(content.includes("Critical"));
  assert.ok(content.includes("Critical \\(CVSS 4.0: 9.9\\)"));
  assert.ok(content.includes("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N"));
});

test("reports the same estimated rating for legacy severity-only findings", () => {
  const content = Buffer.from(createReportPdf({
    id: "estimated-scan",
    projectName: "estimated-project",
    status: "Completed",
    findings: [{ id: "HIGH-1", title: "Legacy finding", severity: "HIGH" }],
    endpoints: [],
  })).toString("latin1");

  assert.ok(content.includes("High \\(Estimated: 8.0\\)"));
});

test("creates a PDF report for scans with no findings", () => {
  const pdf = Buffer.from(createReportPdf({
    id: "empty-scan",
    projectName: "empty-project",
    status: "Completed",
    findings: [],
    endpoints: [],
  }));
  const content = pdf.toString("latin1");

  assert.equal(content.startsWith("%PDF-"), true);
  assert.ok(content.includes("No scanner findings are included in this scan."));
});

test("clearly reports that security findings were not assessed by API Intelligence", () => {
  const content = Buffer.from(createReportPdf({
    id: "route-scan",
    projectName: "route-project",
    status: "Completed",
    findings: [],
    endpoints: [],
    securityFindingsAvailable: false,
  })).toString("latin1");

  assert.ok(content.includes("Security findings were not assessed by this API Intelligence endpoint."));
  assert.ok(content.includes("an empty findings list"));
  assert.ok(content.includes("does not mean the project is secure."));
});

test("paginates long finding fields without wasting a page per line", () => {
  const pdf = Buffer.from(createReportPdf({
    id: "long-scan",
    projectName: "large-report",
    status: "Completed",
    findings: [{
      id: "SG-LONG",
      title: "Long description",
      severity: "Low",
      description: "Long finding details. ".repeat(400),
    }],
    endpoints: [],
  }));
  const content = pdf.toString("latin1");
  const pageCount = (content.match(/\/Type \/Page\b/g) ?? []).length;

  assert.ok(pageCount > 1, "long findings should continue onto another page");
  assert.ok(pageCount < 10, `expected efficient pagination, got ${pageCount} pages`);
});
