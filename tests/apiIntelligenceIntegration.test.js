import assert from "node:assert/strict";
import test from "node:test";
import {
  adaptApiIntelligenceResponse,
  checkApiIntelligenceConnection,
  submitApiIntelligenceScan,
} from "../src/services/apiIntelligenceIntegration.js";

const route = {
  method: "GET",
  path: "/items/{item_id}",
  handler: "read_item",
  file: "app.py",
  line: 12,
  handler_range: { start_line: 12, end_line: 14 },
  security_signals: ["authentication_not_detected_statically"],
  findings: [],
};

function scanResponse(overrides = {}) {
  return {
    status: "completed",
    summary: {
      routes_discovered: 1,
      security_findings_available: false,
    },
    routes: [route],
    unmatched_findings: [],
    openapi_comparison: null,
    errors: [],
    limitations: [],
    ...overrides,
  };
}

test("adapts the API Intelligence contract without inventing security findings", () => {
  const result = adaptApiIntelligenceResponse(scanResponse(), "source-project", "local-1");

  assert.equal(result.id, "local-1");
  assert.equal(result.projectName, "source-project");
  assert.equal(result.isDemo, false);
  assert.equal(result.securityFindingsAvailable, false);
  assert.deepEqual(result.findings, []);
  assert.equal(result.endpoints.length, 1);
  assert.equal(result.endpoints[0].method, "GET");
  assert.equal(result.endpoints[0].path, "/items/{item_id}");
  assert.equal(result.endpoints[0].filePath, "app.py");
  assert.equal(result.endpoints[0].line, 12);
  assert.equal(result.endpoints[0].documented, null);
  assert.deepEqual(result.endpoints[0].parameters, ["item_id · path · required"]);
});

test("uses OpenAPI comparison only when the backend reports it available", () => {
  const result = adaptApiIntelligenceResponse(scanResponse({
    openapi_comparison: {
      available: true,
      undocumented_routes: [{ method: "GET", path: "/items/{item_id}" }],
      documented_operations_not_found: [],
    },
  }), "source-project", "local-2");

  assert.equal(result.endpoints[0].documented, false);
});

test("rejects unsupported or incomplete backend scan responses", () => {
  for (const response of [
    { status: "failed", summary: {}, routes: [] },
    scanResponse({ summary: { security_findings_available: true } }),
    scanResponse({ routes: [{ method: "GET" }] }),
  ]) {
    assert.throws(
      () => adaptApiIntelligenceResponse(response, "source-project"),
      /backend (response|returned)/i,
    );
  }
});

test("does not discard unexpected security findings or incomplete analysis metadata", () => {
  assert.throws(
    () => adaptApiIntelligenceResponse(scanResponse({
      routes: [{ ...route, findings: [{ finding: { rule_id: "B001" } }] }],
    }), "source-project"),
    /security findings that this integration cannot represent/i,
  );
  assert.throws(
    () => adaptApiIntelligenceResponse(scanResponse({ errors: undefined }), "source-project"),
    /completed API Intelligence scan/i,
  );
});

test("posts the source archive using the existing backend multipart contract", async () => {
  const file = Object.assign(new Blob(["zip bytes"], { type: "application/zip" }), {
    name: "source.zip",
  });
  let requestUrl;
  let requestOptions;
  const responseBody = scanResponse();
  const result = await submitApiIntelligenceScan(file, {
    baseUrl: "http://127.0.0.1:8000/",
    fetchImpl: async (url, options) => {
      requestUrl = url;
      requestOptions = options;
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify(responseBody),
      };
    },
  });

  assert.equal(requestUrl, "http://127.0.0.1:8000/api/v1/scan");
  assert.equal(requestOptions.method, "POST");
  assert.equal(requestOptions.body.get("source_zip").name, "source.zip");
  assert.equal(requestOptions.body.get("file"), null);
  assert.deepEqual(result, responseBody);
});

test("reports structured backend errors without falling back to demo data", async () => {
  await assert.rejects(
    submitApiIntelligenceScan(
      Object.assign(new Blob(["invalid"], { type: "application/zip" }), { name: "bad.zip" }),
      {
        baseUrl: "http://127.0.0.1:8000",
        fetchImpl: async () => ({
          ok: false,
          status: 422,
          statusText: "Unprocessable Entity",
          text: async () => JSON.stringify({
            error: { kind: "invalid_zip", message: "The uploaded file is not a valid ZIP archive." },
          }),
        }),
      },
    ),
    /Backend request failed \(422\): The uploaded file is not a valid ZIP archive\./,
  );
});

test("reports invalid response JSON and missing backend configuration", async () => {
  const file = Object.assign(new Blob(["zip"], { type: "application/zip" }), { name: "source.zip" });
  await assert.rejects(
    submitApiIntelligenceScan(file, {
      baseUrl: "http://127.0.0.1:8000",
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        text: async () => "<html>not JSON</html>",
      }),
    }),
    /Backend returned invalid JSON \(200\)/,
  );
  await assert.rejects(
    submitApiIntelligenceScan(file, { baseUrl: "" }),
    /Backend is not configured/,
  );
});

test("checks backend reachability with OPTIONS and does not upload data", async () => {
  let requestUrl;
  let requestOptions;
  const connected = await checkApiIntelligenceConnection({
    baseUrl: "http://127.0.0.1:8000/",
    fetchImpl: async (url, options) => {
      requestUrl = url;
      requestOptions = options;
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "ok" }),
      };
    },
  });

  assert.equal(connected, true);
  assert.equal(requestUrl, "http://127.0.0.1:8000/api/v1/scan");
  assert.deepEqual(requestOptions, { method: "OPTIONS" });
});

test("surfaces unavailable and invalid connection-check responses", async () => {
  await assert.rejects(
    checkApiIntelligenceConnection({
      baseUrl: "http://127.0.0.1:8000",
      fetchImpl: async () => ({ ok: false, status: 404 }),
    }),
    /Backend connection check failed \(404\)/,
  );
  await assert.rejects(
    checkApiIntelligenceConnection({
      baseUrl: "http://127.0.0.1:8000",
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "other-service" }),
      }),
    }),
    /did not identify itself as the API Intelligence backend/,
  );
});
