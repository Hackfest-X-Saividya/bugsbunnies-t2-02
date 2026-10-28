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

test("accepts a ZIP file at the 50 MB limit", () => {
  assert.equal(validateProjectFile({ name: "project.zip", size: 50 * 1024 * 1024 }), "");
});

test("rejects a ZIP file larger than 50 MB", () => {
  assert.equal(
    validateProjectFile({ name: "project.zip", size: 50 * 1024 * 1024 + 1 }),
    "The file exceeds the 50 MB limit. Please upload a smaller file.",
  );
});

test("continues to reject non-ZIP files", () => {
  assert.equal(
    validateProjectFile({ name: "project.txt", size: 1024 }),
    "Choose a ZIP archive containing your Python or FastAPI project.",
  );
});
