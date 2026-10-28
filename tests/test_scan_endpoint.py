import io
import json
import unittest
import zipfile
from unittest.mock import patch
from wsgiref.util import setup_testing_defaults

from api_intelligence.http_api import ENDPOINT_PATH, EXPLAIN_PATH, application


class ScanEndpointTests(unittest.TestCase):
    boundary = "scan-endpoint-test-boundary"

    def zip_bytes(self, files):
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            for name, content in files.items():
                archive.writestr(name, content)
        return archive_buffer.getvalue()

    def multipart_body(self, fields):
        parts = []
        for name, filename, content, content_type in fields:
            parts.extend(
                [
                    f"--{self.boundary}\r\n".encode(),
                    (
                        f'Content-Disposition: form-data; name="{name}"; '
                        f'filename="{filename}"\r\n'
                    ).encode(),
                    f"Content-Type: {content_type}\r\n\r\n".encode(),
                    content,
                    b"\r\n",
                ]
            )
        parts.append(f"--{self.boundary}--\r\n".encode())
        return b"".join(parts)

    def request(self, fields, body=None, method="POST", path=ENDPOINT_PATH):
        request_body = body if body is not None else self.multipart_body(fields)
        environ = {}
        setup_testing_defaults(environ)
        environ.update(
            {
                "REQUEST_METHOD": method,
                "PATH_INFO": path,
                "CONTENT_TYPE": f"multipart/form-data; boundary={self.boundary}",
                "CONTENT_LENGTH": str(len(request_body)),
                "wsgi.input": io.BytesIO(request_body),
            }
        )
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        response_body = b"".join(application(environ, start_response))
        captured["body"] = json.loads(response_body) if response_body else None
        return captured

    def json_request(self, payload, method="POST", path=EXPLAIN_PATH):
        body = json.dumps(payload).encode()
        environ = {}
        setup_testing_defaults(environ)
        environ.update(
            {
                "REQUEST_METHOD": method,
                "PATH_INFO": path,
                "CONTENT_TYPE": "application/json",
                "CONTENT_LENGTH": str(len(body)),
                "wsgi.input": io.BytesIO(body),
            }
        )
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        response_body = b"".join(application(environ, start_response))
        captured["body"] = json.loads(response_body) if response_body else None
        return captured

    def test_accepts_valid_zip_and_returns_scan_summary(self):
        source_zip = self.zip_bytes(
            {
                "app.py": (
                    "from fastapi import FastAPI\n"
                    "app = FastAPI()\n"
                    "@app.get('/items')\n"
                    "def items():\n"
                    "    return []\n"
                )
            }
        )
        result = self.request(
            [("source_zip", "project.zip", source_zip, "application/zip")]
        )

        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["body"]["status"], "completed")
        self.assertEqual(result["body"]["summary"]["routes_discovered"], 1)
        self.assertTrue(result["body"]["summary"]["security_findings_available"])
        self.assertEqual(result["body"]["summary"]["security_findings"], 0)
        self.assertEqual(result["body"]["routes"][0]["path"], "/items")
        self.assertEqual(result["body"]["routes"][0]["findings"], [])
        self.assertEqual(result["body"]["unmatched_findings"], [])
        self.assertIsNone(result["body"]["openapi_comparison"])
        self.assertEqual(result["body"]["errors"], [])

    def test_accepts_optional_openapi_json(self):
        source_zip = self.zip_bytes(
            {
                "app.py": (
                    "from fastapi import FastAPI\n"
                    "app = FastAPI()\n"
                    "@app.get('/items')\n"
                    "def items(): pass\n"
                )
            }
        )
        openapi_json = json.dumps(
            {"openapi": "3.0.0", "paths": {"/items": {"get": {}}}}
        ).encode()
        result = self.request(
            [
                ("source_zip", "project.zip", source_zip, "application/zip"),
                ("openapi_json", "openapi.json", openapi_json, "application/json"),
            ]
        )

        self.assertEqual(result["status"], "200 OK")
        self.assertTrue(result["body"]["openapi_comparison"]["available"])
        self.assertEqual(result["body"]["openapi_comparison"]["undocumented_routes"], [])

    def test_frontend_scan_compatibility_contract(self):
        source_zip = self.zip_bytes({"app.py": "print('safe')\n"})
        result = self.request(
            [("file", "project.zip", source_zip, "application/zip")],
            path="/api/scan",
        )

        self.assertEqual(result["status"], "200 OK")
        scan_id = result["body"]["id"]
        findings = self.request([], method="GET", path=f"/api/scans/{scan_id}/findings")
        routes = self.request([], method="GET", path=f"/api/scans/{scan_id}/routes")
        self.assertEqual(findings["status"], "200 OK")
        self.assertEqual(findings["body"], [])
        self.assertEqual(routes["status"], "200 OK")
        self.assertIsInstance(routes["body"], list)

    def test_accepts_individual_python_source_file(self):
        result = self.request(
            [("source_file", "app.py", b"password = 'example-only'\n", "text/x-python")],
            path=ENDPOINT_PATH,
        )
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["body"]["summary"]["security_findings"], 1)
        self.assertEqual(result["body"]["findings"][0]["file_path"], "app.py")

    def test_accepts_multiple_source_files_and_reports_optional_analyzer_gap(self):
        result = self.request(
            [
                ("files", "app.py", b"print('safe')\n", "text/x-python"),
                ("files", "app.js", b"const value = input;\n", "text/javascript"),
            ],
            path=ENDPOINT_PATH,
        )
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["body"]["summary"]["analysis_status"], "partial")
        self.assertTrue(any(error["code"] == "analyzer_unavailable" for error in result["body"]["errors"]))
        self.assertFalse(result["body"]["summary"]["security_findings_available"])

    def test_accepts_mixed_source_and_supplemental_files_without_claiming_full_analysis(self):
        result = self.request(
            [
                ("files", "app.py", b"print('safe')\n", "text/x-python"),
                ("files", "requirements.txt", b"bandit==1.9.4\n", "text/plain"),
                ("files", "config.yaml", b"debug: false\n", "text/yaml"),
            ],
            path=ENDPOINT_PATH,
        )

        self.assertEqual(result["status"], "200 OK")
        body = result["body"]
        self.assertEqual(body["status"], "partial")
        self.assertEqual(body["summary"]["security_findings"], 0)
        self.assertEqual(body["summary"]["supplemental_files"], 2)
        self.assertEqual(body["summary"]["accepted_files"], 3)
        self.assertEqual(set(body["supplemental_files"]), {"requirements.txt", "config.yaml"})
        analyzed = next(item for item in body["accepted_files"] if item["path"] == "app.py")
        self.assertEqual(analyzed["analysis_status"], "analyzed")

    def test_rejects_real_env_files_but_accepts_env_templates(self):
        rejected = self.request(
            [("files", ".env", b"SECRET=do-not-log\n", "text/plain")],
            path=ENDPOINT_PATH,
        )
        accepted = self.request(
            [("files", ".env.example", b"SECRET=\n", "text/plain")],
            path=ENDPOINT_PATH,
        )

        self.assertEqual(rejected["body"]["error"]["kind"], "env_file_not_allowed")
        self.assertEqual(accepted["body"]["status"], "partial")
        self.assertEqual(accepted["body"]["supplemental_files"], [".env.example"])

    def test_rejects_unsupported_empty_and_binary_source_files(self):
        unsupported = self.request(
            [("source_file", "notes.md", b"# not source", "text/markdown")],
            path=ENDPOINT_PATH,
        )
        empty = self.request(
            [("source_file", "app.py", b"", "text/x-python")],
            path=ENDPOINT_PATH,
        )
        binary = self.request(
            [("source_file", "app.py", b"print(\x00)", "text/x-python")],
            path=ENDPOINT_PATH,
        )
        self.assertEqual(unsupported["body"]["error"]["kind"], "unsupported_file_type")
        self.assertEqual(empty["body"]["error"]["kind"], "empty_source_file")
        self.assertEqual(binary["body"]["error"]["kind"], "binary_source_file")

    def test_rejects_unsafe_and_duplicate_source_paths(self):
        unsafe = self.request(
            [("source_file", "../app.py", b"print('unsafe')\n", "text/x-python")],
            path=ENDPOINT_PATH,
        )
        duplicate = self.request(
            [
                ("files", "app.py", b"print('one')\n", "text/x-python"),
                ("files", "app.py", b"print('two')\n", "text/x-python"),
            ],
            path=ENDPOINT_PATH,
        )
        self.assertEqual(unsafe["body"]["error"]["kind"], "unsafe_source_path")
        self.assertEqual(duplicate["body"]["error"]["kind"], "duplicate_source_path")

    def test_health_endpoint_and_local_cors_origins(self):
        result = self.request([], method="GET", path="/health")
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["body"]["status"], "ok")
        self.assertEqual(
            result["headers"]["Access-Control-Allow-Origin"],
            "http://localhost:5173",
        )

    def test_explanation_endpoint_returns_backend_explanation(self):
        result = self.json_request(
            {
                "endpoint": {"method": "GET", "path": "/items"},
                "findings": [
                    {
                        "title": "Unsafe input handling",
                        "severity": "high",
                        "risk_level": "critical",
                    }
                ],
            }
        )
        self.assertEqual(result["status"], "200 OK")
        self.assertIn("GET /items", result["body"]["explanation"])
        self.assertIn("Unsafe input handling", result["body"]["explanation"])

    def test_explanation_endpoint_validates_json_contract(self):
        result = self.json_request({"endpoint": "not-an-object", "findings": {}})
        self.assertEqual(result["status"], "400 Bad Request")
        self.assertEqual(result["body"]["error"]["kind"], "invalid_explanation_request")

        environ = {}
        setup_testing_defaults(environ)
        environ.update(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/health",
                "HTTP_ORIGIN": "http://127.0.0.1:5173",
                "wsgi.input": io.BytesIO(b""),
            }
        )
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        application(environ, start_response)
        self.assertEqual(
            captured["headers"]["Access-Control-Allow-Origin"],
            "http://127.0.0.1:5173",
        )

    def test_rejects_invalid_zip(self):
        result = self.request(
            [("source_zip", "project.zip", b"not a zip archive", "application/zip")]
        )

        self.assertEqual(result["status"].split()[0], "422")
        self.assertEqual(result["body"]["error"]["kind"], "invalid_zip")

    def test_rejects_unsafe_zip_paths(self):
        for unsafe_path in ("../outside.py", "..\\outside.py", "./outside.py", "C:\\outside.py"):
            with self.subTest(path=unsafe_path):
                source_zip = self.zip_bytes({unsafe_path: "print('unsafe')"})
                result = self.request(
                    [("source_zip", "project.zip", source_zip, "application/zip")]
                )

                self.assertEqual(result["status"].split()[0], "422")
                self.assertEqual(
                    result["body"]["error"]["kind"],
                    "unsafe_archive_path",
                )

    def test_rejects_malformed_openapi_json(self):
        source_zip = self.zip_bytes({"app.py": "pass\n"})
        result = self.request(
            [
                ("source_zip", "project.zip", source_zip, "application/zip"),
                ("openapi_json", "openapi.json", b"{", "application/json"),
            ]
        )

        self.assertEqual(result["status"].split()[0], "422")
        self.assertEqual(result["body"]["error"]["kind"], "invalid_openapi")

    def test_rejects_non_post_requests(self):
        result = self.request([], method="GET")

        self.assertEqual(result["status"], "405 Method Not Allowed")
        self.assertEqual(result["headers"]["Allow"], "POST")
        self.assertEqual(result["body"]["error"]["kind"], "method_not_allowed")

    def test_rejects_oversized_request_body(self):
        source_zip = self.zip_bytes({"app.py": "pass\n"})
        with patch("api_intelligence.http_api.MAX_REQUEST_BYTES", 1):
            result = self.request(
                [("source_zip", "project.zip", source_zip, "application/zip")]
            )

        self.assertEqual(result["status"].split()[0], "413")
        self.assertEqual(result["body"]["error"]["kind"], "request_too_large")

    def test_rejects_archive_that_expands_over_limit(self):
        source_zip = self.zip_bytes({"app.py": "pass\n"})
        with patch("api_intelligence.http_api.MAX_EXTRACTED_BYTES", 1):
            result = self.request(
                [("source_zip", "project.zip", source_zip, "application/zip")]
            )

        self.assertEqual(result["status"].split()[0], "413")
        self.assertEqual(result["body"]["error"]["kind"], "archive_too_large")

    def test_cleans_temporary_extraction_after_scan_failure(self):
        source_zip = self.zip_bytes({"app.py": "pass\n"})
        extracted_paths = []

        def fail_analysis(project_root, **kwargs):
            extracted_paths.append(project_root)
            raise RuntimeError("test scan failure")

        with patch("api_intelligence.http_api.analyze_project", side_effect=fail_analysis):
            with self.assertLogs("api_intelligence.http_api", level="ERROR"):
                result = self.request(
                    [("source_zip", "project.zip", source_zip, "application/zip")]
                )

        self.assertEqual(result["status"].split()[0], "500")
        self.assertEqual(result["body"]["error"]["kind"], "scan_failed")
        self.assertEqual(len(extracted_paths), 1)
        self.assertFalse(extracted_paths[0].exists())


if __name__ == "__main__":
    unittest.main()
