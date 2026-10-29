import assert from "node:assert/strict";
import test from "node:test";
import { normalizeScanResponse } from "../src/services/api.js";

test("normalizes successful live scan responses with zero findings", () => {
  const scan = normalizeScanResponse({
    status: "completed",
    summary: { security_findings_available: true, security_findings: 0 },
    security_findings: [],
    routes: [{
      method: "GET",
      path: "/hello",
      file: "app.py",
      line: 3,
      findings: [],
    }],
    unmatched_findings: [],
    errors: [],
    limitations: [],
  });

  assert.equal(scan.securityFindingsAvailable, true);
  assert.deepEqual(scan.findings, []);
  assert.equal(scan.endpoints.length, 1);
  assert.equal(scan.endpoints[0].path, "/hello");
});

test("normalizes and correlates real finding metadata from the backend", () => {
  const finding = {
    id: "B307:app.py:8",
    rule_id: "B307",
    title: "Possibly insecure function",
    description: "Use of eval.",
    severity: "medium",
    file_path: "app.py",
    line: 8,
    evidence: 'return eval("1 + 1")',
  };
  const scan = normalizeScanResponse({
    status: "completed",
    summary: { security_findings_available: true, security_findings: 1 },
    security_findings: [finding],
    routes: [{
      method: "GET",
      path: "/unsafe",
      file: "app.py",
      line: 6,
      findings: [{ finding, correlation: "handler_range" }],
    }],
    unmatched_findings: [],
    errors: [],
    limitations: [],
  });

  assert.equal(scan.findings.length, 1);
  assert.equal(scan.findings[0].ruleId, "B307");
  assert.equal(scan.findings[0].severity, "Medium");
  assert.equal(scan.findings[0].filePath, "app.py");
  assert.equal(scan.findings[0].line, 8);
  assert.equal(scan.findings[0].evidence, 'return eval("1 + 1")');
  assert.equal(scan.findings[0].endpoint, "GET /unsafe");
  assert.deepEqual(scan.endpoints[0].findings, ["B307:app.py:8"]);
});
