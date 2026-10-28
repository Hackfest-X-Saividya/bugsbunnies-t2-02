import assert from "node:assert/strict";
import test from "node:test";
import {
  countFindingsBySeverity,
  formatFindingRating,
  getFindingRatingPresentation,
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
  assert.equal(rating.numericScore, 8.0);
  assert.equal(rating.scoreSource, "Estimated");
  assert.equal(formatFindingRating(rating), "High (Estimated: 8.0)");
  assert.match(rating.scoreNote, /not a CVSS score/i);
});

test("uses fixed documented estimates for known severities only", () => {
  const cases = [
    ["Critical", 9.5],
    ["HIGH", 8.0],
    ["Medium", 5.5],
    ["LOW", 2.5],
    ["None", 0.0],
  ];

  for (const [severity, score] of cases) {
    const rating = resolveFindingRating({ severity });
    assert.equal(rating.numericScore, score);
    assert.equal(rating.scoreSource, "Estimated");
    assert.equal(rating.cvssScore, null);
    assert.equal(formatFindingRating(rating), `${severity[0].toUpperCase()}${severity.slice(1).toLowerCase()} (Estimated: ${score.toFixed(1)})`);
  }
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
  assert.equal(rating.numericScore, null);
  assert.equal(formatFindingRating(rating), "Informational (Not rated)");
  assert.match(rating.scoreNote, /not assigned a CVSS score/i);
});

test("unknown severity stays unrated instead of receiving an estimate", () => {
  const rating = resolveFindingRating({ severity: "unclassified" });

  assert.equal(rating.severity, "Unrated");
  assert.equal(rating.numericScore, null);
  assert.equal(formatFindingRating(rating), "Unrated (Not rated)");
});

test("verified CVSS score is formatted as CVSS, not as an estimate", () => {
  const rating = resolveFindingRating({
    severity: "low",
    cvss_version: "4.0",
    cvss_score: 9.9,
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
    cvss_calculated: true,
  });

  assert.equal(formatFindingRating(rating), "Critical (CVSS 4.0: 9.9)");
});

test("finding rating UI presentation labels estimated, CVSS, and unavailable scores", () => {
  const estimated = getFindingRatingPresentation({ severity: "MEDIUM" });
  assert.equal(estimated.rating.severity, "Medium");
  assert.equal(estimated.scoreLabel, "Estimated · 5.5");
  assert.match(estimated.scoreDescription, /not a CVSS score/i);

  const verified = getFindingRatingPresentation({
    severity: "low",
    cvss_version: "4.0",
    cvss_score: 9.9,
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
    cvss_calculated: true,
  });
  assert.equal(verified.scoreLabel, "CVSS 4.0 · 9.9");

  const unrated = getFindingRatingPresentation({ severity: "informational" });
  assert.equal(unrated.scoreLabel, "Not rated");
  assert.match(unrated.scoreDescription, /not assigned a CVSS score/i);
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
