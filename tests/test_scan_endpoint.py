import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from wsgiref.util import setup_testing_defaults

from api_intelligence.http_api import ENDPOINT_PATH, RequestError, _extract_archive, application
from src.zeroshadow_security.models import ScanResult, ScanStatus, ScannerError


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

    def request(
        self,
        fields,
        body=None,
        method="POST",
        path=ENDPOINT_PATH,
        origin=None,
        requested_method=None,
        requested_headers=None,
    ):
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
        if origin:
            environ["HTTP_ORIGIN"] = origin
        if requested_method:
            environ["HTTP_ACCESS_CONTROL_REQUEST_METHOD"] = requested_method
        if requested_headers:
            environ["HTTP_ACCESS_CONTROL_REQUEST_HEADERS"] = requested_headers
        captured = {}

        def start_response(status, headers, exc_info=None):
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
        self.assertIsInstance(
            result["body"]["summary"]["security_findings_available"],
            bool,
        )
        self.assertEqual(result["body"]["routes"][0]["path"], "/items")
        self.assertEqual(result["body"]["routes"][0]["findings"], [])
        self.assertEqual(result["body"]["security_findings"], [])
        self.assertEqual(result["body"]["unmatched_findings"], [])
        self.assertIsNone(result["body"]["openapi_comparison"])
        self.assertEqual(result["body"]["errors"], [])

    def test_returns_bandit_findings_and_correlates_them_to_routes(self):
        executable = Path(sys.prefix) / "bin" / "bandit"
        if not executable.is_file() and not shutil.which("bandit"):
            self.skipTest("Bandit is not installed in this Python environment")

        sample_path = Path(__file__).parent / "fixtures" / "bandit_sample" / "app.py"
        source_zip = self.zip_bytes({"app.py": sample_path.read_text(encoding="utf-8")})
        result = self.request(
            [("source_zip", "project.zip", source_zip, "application/zip")]
        )

        self.assertEqual(result["status"], "200 OK")
        body = result["body"]
        self.assertTrue(body["summary"]["security_findings_available"])
        self.assertEqual(body["summary"]["security_findings"], 1)
        finding = body["security_findings"][0]
        self.assertEqual(finding["rule_id"], "B307")
        self.assertEqual(finding["severity"], "medium")
        self.assertIn("possibly insecure function", finding["description"])
        self.assertEqual(finding["file_path"], "app.py")
        self.assertEqual(finding["line"], 8)
        self.assertIn("eval(", finding["evidence"])
        self.assertEqual(body["routes"][0]["path"], "/unsafe")
        self.assertEqual(
            body["routes"][0]["findings"][0]["finding"]["id"],
            finding["id"],
        )
        self.assertEqual(body["unmatched_findings"], [])
        self.assertEqual(body["security_scan_errors"], [])

    def test_reports_scanner_failure_without_claiming_findings_are_available(self):
        source_zip = self.zip_bytes({"app.py": "pass\n"})
        failed_result = ScanResult(
            ScanStatus.FAILED,
            errors=[
                ScannerError(
                    "Bandit executable was not found",
                    "missing_executable",
                    "/private/path/to/environment",
                )
            ],
        )
        with patch(
            "api_intelligence.http_api.SecurityIntelligenceService.scan",
            return_value=failed_result,
        ):
            result = self.request(
                [("source_zip", "project.zip", source_zip, "application/zip")]
            )

        body = result["body"]
        self.assertEqual(result["status"], "200 OK")
        self.assertFalse(body["summary"]["security_findings_available"])
        self.assertEqual(body["security_findings"], [])
        self.assertEqual(
            body["security_scan_errors"],
            [
                {
                    "code": "missing_executable",
                    "message": "Bandit executable was not found",
                    "stage": "security_scan",
                }
            ],
        )
        self.assertNotIn("/private/path", json.dumps(body))

    def test_preflight_allows_local_frontend_origin(self):
        result = self.request(
            [],
            body=b"",
            method="OPTIONS",
            origin="http://localhost:5173",
            requested_method="POST",
            requested_headers="content-type",
        )

        self.assertEqual(result["status"], "204 No Content")
        self.assertEqual(
            result["headers"]["Access-Control-Allow-Origin"],
            "http://localhost:5173",
        )
        self.assertEqual(result["headers"]["Access-Control-Allow-Methods"], "POST, OPTIONS")
        self.assertEqual(result["headers"]["Access-Control-Allow-Headers"], "Content-Type")

    def test_scan_response_allows_local_frontend_origin(self):
        source_zip = self.zip_bytes({"app.py": "pass\n"})
        result = self.request(
            [("source_zip", "project.zip", source_zip, "application/zip")],
            origin="http://127.0.0.1:5173",
        )

        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(
            result["headers"]["Access-Control-Allow-Origin"],
            "http://127.0.0.1:5173",
        )

    def test_preflight_rejects_untrusted_origin(self):
        result = self.request(
            [],
            body=b"",
            method="OPTIONS",
            origin="https://attacker.example",
            requested_method="POST",
        )

        self.assertEqual(result["status"], "403 Forbidden")
        self.assertNotIn("Access-Control-Allow-Origin", result["headers"])

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

    def test_rejects_invalid_zip(self):
        result = self.request(
            [("source_zip", "project.zip", b"not a zip archive", "application/zip")]
        )

        self.assertEqual(result["status"].split()[0], "422")
        self.assertEqual(result["body"]["error"]["kind"], "invalid_zip")

    def test_rejects_non_zip_file_named_zip(self):
        result = self.request(
            [("source_zip", "renamed.zip", b"plain text, not a ZIP", "application/zip")]
        )

        self.assertEqual(result["status"].split()[0], "422")
        self.assertEqual(result["body"]["error"]["kind"], "invalid_zip")

    def test_rejects_corrupted_zip_before_extracting_files(self):
        source_zip = bytearray(self.zip_bytes({"app.py": "print('valid data')\n"}))
        with zipfile.ZipFile(io.BytesIO(source_zip)) as archive:
            entry = archive.getinfo("app.py")
        filename_length = int.from_bytes(
            source_zip[entry.header_offset + 26 : entry.header_offset + 28],
            "little",
        )
        extra_length = int.from_bytes(
            source_zip[entry.header_offset + 28 : entry.header_offset + 30],
            "little",
        )
        data_offset = entry.header_offset + 30 + filename_length + extra_length
        source_zip[data_offset] ^= 0xFF

        with tempfile.TemporaryDirectory() as directory:
            extraction_root = Path(directory)
            with self.assertRaises(RequestError) as raised:
                _extract_archive(bytes(source_zip), extraction_root)
            self.assertEqual(raised.exception.kind, "invalid_zip")
            self.assertEqual(list(extraction_root.iterdir()), [])

        with patch("api_intelligence.http_api.analyze_project") as analyze_project:
            result = self.request(
                [("source_zip", "project.zip", bytes(source_zip), "application/zip")]
            )

        self.assertEqual(result["status"].split()[0], "422")
        self.assertEqual(result["body"]["error"]["kind"], "invalid_zip")
        analyze_project.assert_not_called()

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
        self.assertEqual(result["headers"]["Allow"], "POST, OPTIONS")
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
