import assert from "node:assert/strict";
import test from "node:test";
import { createReportPdf } from "../src/services/reportPdf.js";
import {
  SCAN_HISTORY_STORAGE_KEY,
  addLiveScan,
  createScanHistoryState,
  readScanHistory,
  selectLiveScan,
  writeScanHistory,
} from "../src/services/scanHistory.js";

function liveScan(id, findings = []) {
  return {
    id,
    projectName: `project-${id}`,
    status: "Complete",
    completedAt: `2026-10-29T00:00:0${id.endsWith("1") ? "1" : "2"}.000Z`,
    isDemo: false,
    securityFindingsAvailable: true,
    findings,
    endpoints: [{
      id: `${id}-route`,
      method: "GET",
      path: "/items",
      filePath: "app.py",
      line: 3,
      findings: findings.map((finding) => finding.id),
      routeFindingObjects: findings,
    }],
    backendErrors: [],
    limitations: [],
  };
}

test("keeps a completed zero-finding scan as a real live scan", () => {
  const state = addLiveScan(createScanHistoryState(), liveScan("live-1"));

  assert.equal(state.scans.length, 1);
  assert.equal(state.scans[0].isDemo, false);
  assert.deepEqual(state.scans[0].findings, []);
  assert.equal(state.selectedScanId, "live-1");
});

test("never inserts demo samples into live scan history", () => {
  const initial = createScanHistoryState();
  const result = addLiveScan(initial, {
    ...liveScan("demo-sample"),
    isDemo: true,
  });

  assert.equal(result, initial);
  assert.deepEqual(result.scans, []);
});

test("keeps positive findings and selects a requested scan", () => {
  const first = liveScan("live-1");
  const second = liveScan("live-2", [{ id: "B307:app.py:8", severity: "Medium" }]);
  const state = addLiveScan(addLiveScan(createScanHistoryState(), first), second);
  const selected = selectLiveScan(state, first.id);

  assert.equal(selected.selectedScanId, first.id);
  assert.equal(selected.scans.find((scan) => scan.id === "live-2").findings.length, 1);
  assert.equal(selectLiveScan(selected, "not-present"), selected);
});

test("persists selected scans without persisting finding evidence or source snippets", () => {
  const storageValues = new Map();
  const storage = {
    getItem: (key) => storageValues.get(key) ?? null,
    setItem: (key, value) => storageValues.set(key, value),
  };
  const scan = liveScan("live-2", [{
    id: "B307:app.py:8",
    title: "Use of possibly insecure function",
    severity: "Medium",
    filePath: "app.py",
    line: 8,
    evidence: 'return eval("secret source")',
    code: 'return eval("secret source")',
  }]);
  const state = addLiveScan(createScanHistoryState(), scan);

  assert.equal(writeScanHistory(storage, state), "");
  const serialized = storageValues.get(SCAN_HISTORY_STORAGE_KEY);
  assert.equal(serialized.includes("secret source"), false);
  assert.equal(serialized.includes("routeFindingObjects"), false);

  const restored = readScanHistory(storage);
  assert.equal(restored.error, "");
  assert.equal(restored.selectedScanId, "live-2");
  assert.equal(restored.scans[0].findings.length, 1);
  assert.equal(restored.scans[0].findings[0].line, 8);
  assert.equal("evidence" in restored.scans[0].findings[0], false);
  assert.equal("code" in restored.scans[0].findings[0], false);
});

test("a report generated from the restored selection contains that scan's own data", () => {
  const storageValues = new Map();
  const storage = {
    getItem: (key) => storageValues.get(key) ?? null,
    setItem: (key, value) => storageValues.set(key, value),
  };
  const empty = liveScan("live-empty");
  const positive = liveScan("live-positive", [{
    id: "B307:app.py:8",
    title: "Use of possibly insecure function",
    severity: "Medium",
    filePath: "app.py",
    line: 8,
    endpoint: "GET /unsafe",
    endpointId: "live-positive-route",
    description: "Bandit detected eval.",
  }]);
  const state = addLiveScan(addLiveScan(createScanHistoryState(), empty), positive);

  assert.equal(writeScanHistory(storage, selectLiveScan(state, empty.id)), "");
  const restoredEmpty = readScanHistory(storage).scans
    .find((scan) => scan.id === empty.id);
  const emptyPdf = Buffer.from(createReportPdf(restoredEmpty)).toString("latin1");
  assert.ok(emptyPdf.includes("project-live-empty"));
  assert.ok(emptyPdf.includes("0 potential scanner findings"));
  assert.equal(emptyPdf.includes("B307"), false);

  assert.equal(writeScanHistory(storage, selectLiveScan(state, positive.id)), "");
  const restoredPositive = readScanHistory(storage).scans
    .find((scan) => scan.id === positive.id);
  const positivePdf = Buffer.from(createReportPdf(restoredPositive)).toString("latin1");
  assert.ok(positivePdf.includes("project-live-positive"));
  assert.ok(positivePdf.includes("B307:app.py:8"));
  assert.ok(positivePdf.includes("app.py"));
  assert.ok(positivePdf.includes("GET /unsafe"));
});

test("storage access failures are reported without throwing", () => {
  const storage = {
    getItem() { throw new Error("blocked"); },
    setItem() { throw new Error("blocked"); },
  };
  assert.match(readScanHistory(storage).error, /could not be read/);
  assert.match(writeScanHistory(storage, createScanHistoryState()), /could not be saved/);
});
