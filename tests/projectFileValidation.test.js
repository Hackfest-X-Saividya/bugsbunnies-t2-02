import assert from "node:assert/strict";
import test from "node:test";
import { validateProjectFile } from "../src/services/projectFileValidation.js";

test("rejects empty files with a clear message", () => {
  assert.equal(
    validateProjectFile({ name: "project.zip", size: 0 }),
    "The file is empty. Please upload a file containing data.",
  );
});

test("accepts a nonempty ZIP file", () => {
  assert.equal(validateProjectFile({ name: "project.zip", size: 1024 }), "");
});
