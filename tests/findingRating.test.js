import assert from "node:assert/strict";
import test from "node:test";
import {
  countFindingsBySeverity,
  resolveFindingRating,
  severityFromCvssScore,
} from "../src/services/findingRating.js";

test("maps CVSS score boundaries to severity labels", () => {
  const cases = [
    [0, "None"],
    [0.1, "Low"],
    [3.9, "Low"],
    [4, "Medium"],
    [6.9, "Medium"],
    [7, "High"],
    [8.9, "High"],
    [9, "Critical"],
    [10, "Critical"],
  ];

  for (const [score, expected] of cases) {
    assert.equal(severityFromCvssScore(score), expected);
  }
});

test("does not map invalid or unavailable scores", () => {
  for (const score of [null, undefined, -0.1, 10.1, 8.95, Number.NaN, "7.0"]) {
    assert.equal(severityFromCvssScore(score), null);
  }
  assert.equal(resolveFindingRating({ severity: "HIGH" }).cvssScore, null);
});

test("does not accept a score without a backend-calculated CVSS rating", () => {
  assert.equal(
    resolveFindingRating({
      severity: "High",
      cvssVersion: "4.0",
      cvssScore: 9.1,
      cvssVector: "CVSS:4.0/AV:N",
    }).severity,
    "High",
  );
  assert.equal(
    resolveFindingRating({
      severity: "High",
      cvssVersion: "4.0",
      cvssScore: 0.0,
      cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
    }).cvssScore,
    null,
  );
});

test("uses backend-calculated scores for severity instead of raw scanner labels", () => {
  const rating = resolveFindingRating({
    severity: "low",
    cvss_version: "4.0",
    cvss_score: 9.9,
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
    cvss_calculated: true,
  });

  assert.equal(rating.severity, "Critical");
  assert.equal(rating.cvssScore, 9.9);
});

test("requires matching CVSS version and a valid one-decimal score", () => {
  const vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N";
  for (const [cvssVersion, cvssScore] of [["3.1", 9.9], ["4.0", 9.95]]) {
    const rating = resolveFindingRating({
      severity: "Low",
      cvss_version: cvssVersion,
      cvss_score: cvssScore,
      cvss_vector: vector,
      cvss_calculated: true,
    });

    assert.equal(rating.cvssScore, null);
    assert.equal(rating.severity, "Low");
  }
});

test("preserves scanner severity when CVSS metrics are unavailable", () => {
  const rating = resolveFindingRating({ severity: "HIGH" });

  assert.equal(rating.severity, "High");
  assert.equal(rating.cvssScore, null);
  assert.match(rating.scoreNote, /no valid backend-calculated CVSS rating/i);
});

test("rejects backend snake-case score fields with incomplete metrics", () => {
  const rating = resolveFindingRating({
    severity: "HIGH",
    cvss_version: "4.0",
    cvss_score: 9.1,
    cvss_vector: "CVSS:4.0/AV:N",
  });

  assert.equal(rating.cvssScore, null);
  assert.equal(rating.severity, "High");
});

test("ignores unverified CVSS vectors with incomplete metrics", () => {
  const rating = resolveFindingRating({
    severity: "Low",
    cvssVersion: "4.0",
    cvssScore: 9.1,
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H",
  });

  assert.equal(rating.severity, "Low");
  assert.equal(rating.cvssScore, null);
});

test("informational findings never receive a CVSS score", () => {
  const rating = resolveFindingRating({
    severity: "Informational",
    cvssVersion: "4.0",
    cvssScore: "ignored",
    cvssVector: "not-a-vector",
  });

  assert.equal(rating.severity, "Informational");
  assert.equal(rating.cvssScore, null);
  assert.match(rating.scoreNote, /not assigned a CVSS score/i);
});

test("dashboard severity counts include Critical findings from the chart data", () => {
  const counts = countFindingsBySeverity([
    {
      severity: "low",
      cvss_version: "4.0",
      cvss_score: 9.9,
      cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
      cvss_calculated: true,
    },
    { severity: "HIGH" },
    { severity: "Informational" },
  ]);

  assert.equal(counts.Critical, 1);
  assert.equal(counts.High, 1);
  assert.equal(counts.Informational, 1);
});
