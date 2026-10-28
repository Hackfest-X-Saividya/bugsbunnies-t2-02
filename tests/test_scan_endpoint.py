import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from wsgiref.util import setup_testing_defaults

from api_intelligence.http_api import ENDPOINT_PATH, RequestError, _extract_archive, application


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
        self.assertFalse(result["body"]["summary"]["security_findings_available"])
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
