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
  ]) {
    assert.ok(content.includes(value), `PDF should contain ${value}`);
  }
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
