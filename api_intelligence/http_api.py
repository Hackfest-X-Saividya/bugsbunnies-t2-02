"""Minimal standard-library WSGI endpoint for API Intelligence scans."""

from __future__ import annotations

import io
import json
import logging
import ntpath
import os
import re
import stat
import tempfile
import zlib
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from http import HTTPStatus
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from wsgiref.simple_server import make_server
from zipfile import BadZipFile, ZipFile

from .route_discovery import analyze_project
from zeroshadow_security.analyzers import accepted_extensions, language_for_path, scan_project
from zeroshadow_security.adapter import to_security_errors, to_security_findings

LOGGER = logging.getLogger(__name__)
ENDPOINT_PATH = "/api/v1/scan"
FRONTEND_SCAN_PATH = "/api/scan"
FRONTEND_SCANS_PREFIX = "/api/scans/"
HEALTH_PATH = "/health"
MAX_REQUEST_BYTES = 20 * 1024 * 1024
MAX_OPENAPI_BYTES = 2 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 5000
MAX_MULTIPART_BOUNDARY_BYTES = 70
BOUNDARY_PATTERN = re.compile(r"[0-9A-Za-z'()+_,./:=?-]+\Z")
CHUNK_SIZE = 64 * 1024
_SCAN_RESULTS: dict[str, dict[str, Any]] = {}
_NEXT_SCAN_ID = 1
MAX_STORED_SCANS = 100
MAX_SOURCE_FILES = 50
MAX_SOURCE_FILE_BYTES = 5 * 1024 * 1024
ACCEPTED_EXTENSIONS = set(accepted_extensions())


@dataclass(frozen=True)
class UploadedSource:
    filename: str
    content: bytes


@dataclass(frozen=True)
class UploadBundle:
    source_zip: bytes | None
    source_files: tuple[UploadedSource, ...]
    openapi_json: bytes | None


class RequestError(Exception):
    def __init__(self, status: HTTPStatus, kind: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.kind = kind
        self.message = message


def _json_response(
    start_response: Callable[..., Any],
    status: HTTPStatus,
    body: dict[str, Any],
    extra_headers: list[tuple[str, str]] | None = None,
    cors_origin: str = "http://localhost:5173",
) -> list[bytes]:
    encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    start_response(
        f"{status.value} {status.phrase}",
        [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(encoded))),
            ("Access-Control-Allow-Origin", cors_origin),
            ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
            ("Access-Control-Allow-Headers", "Content-Type"),
        ]
        + (extra_headers or []),
    )
    return [encoded]


def _read_request_body(environ: dict[str, Any]) -> bytes:
    raw_length = environ.get("CONTENT_LENGTH", "")
    try:
        content_length = int(raw_length)
    except (TypeError, ValueError):
        raise RequestError(
            HTTPStatus.LENGTH_REQUIRED,
            "content_length_required",
            "A valid Content-Length header is required.",
        ) from None
    if content_length <= 0:
        raise RequestError(
            HTTPStatus.BAD_REQUEST,
            "empty_request",
            "The multipart request body must not be empty.",
        )
    if content_length > MAX_REQUEST_BYTES:
        raise RequestError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "request_too_large",
            "The request exceeds the maximum upload size.",
        )

    stream = environ.get("wsgi.input")
    if stream is None:
        raise RequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
            "The request body is unavailable.",
        )
    body = stream.read(content_length)
    if len(body) != content_length:
        raise RequestError(
            HTTPStatus.BAD_REQUEST,
            "incomplete_request",
            "The request body length does not match Content-Length.",
        )
    return body


def _parse_multipart(content_type: str, body: bytes) -> UploadBundle:
    content_headers = Message()
    content_headers["Content-Type"] = content_type
    boundary = content_headers.get_param("boundary", header="content-type")
    if content_headers.get_content_type().lower() != "multipart/form-data":
        raise RequestError(
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Content-Type must be multipart/form-data.",
        )
    if not isinstance(boundary, str):
        raise RequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_multipart",
            "A multipart boundary is required.",
        )
    if (
        len(boundary.encode("ascii", errors="ignore")) > MAX_MULTIPART_BOUNDARY_BYTES
        or not BOUNDARY_PATTERN.fullmatch(boundary)
    ):
        raise RequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_multipart",
            "The multipart boundary is invalid.",
        )

    headers = (
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        "MIME-Version: 1.0\r\n\r\n"
    ).encode("ascii")
    try:
        message = BytesParser(policy=policy.default).parsebytes(headers + body)
    except (ValueError, UnicodeError):
        raise RequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_multipart",
            "The multipart form data could not be parsed.",
        ) from None
    if not message.is_multipart():
        raise RequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_multipart",
            "The multipart form data could not be parsed.",
        )

    source_zip: UploadedSource | None = None
    source_files: list[UploadedSource] = []
    openapi_json: bytes | None = None
    openapi_filename: str | None = None
    for part in message.iter_parts():
        field_name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        if field_name not in {"source_zip", "file", "source_file", "files", "openapi_json"} or filename is None:
            raise RequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_form_field",
                "Use source_zip, file, source_file, files, or optional openapi_json fields.",
            )
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            raise RequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_form_field",
                f"The {field_name} upload is invalid.",
            )
        if field_name == "openapi_json":
            if openapi_json is not None:
                raise RequestError(HTTPStatus.BAD_REQUEST, "duplicate_form_field", "The openapi_json field may be supplied only once.")
            openapi_json = payload
            openapi_filename = filename
            continue
        if not payload:
            raise RequestError(HTTPStatus.UNPROCESSABLE_ENTITY, "empty_source_file", "Uploaded source files must not be empty.")
        is_archive = field_name == "source_zip" or (field_name == "file" and Path(filename).suffix.lower() == ".zip")
        if len(payload) > (MAX_REQUEST_BYTES if is_archive else MAX_SOURCE_FILE_BYTES):
            raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "source_file_too_large", "A source file exceeds the configured size limit.")
        if not is_archive and b"\x00" in payload:
            raise RequestError(HTTPStatus.UNPROCESSABLE_ENTITY, "binary_source_file", "Binary files are not accepted as source code.")
        source = UploadedSource(filename, payload)
        if field_name == "source_zip" or (field_name == "file" and Path(filename).suffix.lower() == ".zip"):
            if source_zip is not None:
                raise RequestError(HTTPStatus.BAD_REQUEST, "duplicate_form_field", "The source_zip field may be supplied only once.")
            source_zip = source
        else:
            source_files.append(source)

    if source_zip is not None and source_files:
        raise RequestError(HTTPStatus.BAD_REQUEST, "conflicting_source_inputs", "Provide a ZIP archive or source files, not both.")
    if source_zip is None and not source_files:
        raise RequestError(
            HTTPStatus.BAD_REQUEST,
            "source_input_required",
            "Provide a source_zip archive, file source, or files source inputs.",
        )
    if source_zip is not None and Path(source_zip.filename).suffix.lower() != ".zip":
        raise RequestError(
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "unsupported_file_type",
            "The source_zip upload must have a .zip extension.",
        )
    if len(source_files) > MAX_SOURCE_FILES:
        raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_many_source_files", "Too many source files were uploaded.")
    for source in source_files:
        if Path(source.filename).suffix.lower() not in ACCEPTED_EXTENSIONS or language_for_path(source.filename) is None:
            accepted = ", ".join(sorted(ACCEPTED_EXTENSIONS))
            raise RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "unsupported_file_type", f"Unsupported source extension. Accepted extensions: {accepted}.")
    if openapi_json is not None:
        if len(openapi_json) > MAX_OPENAPI_BYTES:
            raise RequestError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "openapi_too_large",
                "The OpenAPI JSON upload exceeds the maximum size.",
            )
        if not openapi_filename or Path(openapi_filename).suffix.lower() != ".json":
            raise RequestError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_file_type",
                "The openapi_json upload must be a .json file.",
            )
    return UploadBundle(
        source_zip=source_zip.content if source_zip is not None else None,
        source_files=tuple(source_files),
        openapi_json=openapi_json,
    )


def _validate_openapi(openapi_bytes: bytes | None) -> dict[str, Any] | None:
    if openapi_bytes is None:
        return None
    try:
        document = json.loads(openapi_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise RequestError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "invalid_openapi",
            "The OpenAPI upload must be valid UTF-8 encoded JSON.",
        ) from None
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise RequestError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "invalid_openapi",
            "The OpenAPI JSON must be an object containing a paths object.",
        )
    return document


def _safe_archive_path(root: Path, raw_name: str) -> tuple[Path, bool]:
    if not raw_name or "\x00" in raw_name:
        raise RequestError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "unsafe_archive_path",
            "The ZIP archive contains an invalid entry path.",
        )
    normalized_name = raw_name.replace("\\", "/")
    is_directory = normalized_name.endswith("/")
    components = normalized_name.split("/")
    if is_directory:
        components.pop()
    drive, _ = ntpath.splitdrive(raw_name)
    if (
        drive
        or normalized_name.startswith("/")
        or not components
        or any(part in {"", ".", ".."} for part in components)
    ):
        raise RequestError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "unsafe_archive_path",
            "The ZIP archive contains an absolute or traversing entry path.",
        )

    archive_path = PurePosixPath(*components)
    destination = root.joinpath(*archive_path.parts)
    try:
        destination.resolve().relative_to(root.resolve())
    except ValueError:
        raise RequestError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "unsafe_archive_path",
            "The ZIP archive contains an entry outside the extraction directory.",
        ) from None
    return destination, is_directory


def _extract_archive(archive_bytes: bytes, root: Path) -> None:
    try:
        archive = ZipFile(io.BytesIO(archive_bytes))
    except (BadZipFile, OSError, ValueError):
        raise RequestError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "invalid_zip",
            "The source upload is not a valid ZIP archive.",
        ) from None

    extracted_total = 0
    seen_paths: set[str] = set()
    try:
        with archive:
            entries = archive.infolist()
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                raise RequestError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "archive_too_large",
                    "The ZIP archive contains too many entries.",
                )
            for entry in entries:
                destination, is_directory = _safe_archive_path(root, entry.filename)
                normalized_key = destination.as_posix().casefold()
                if normalized_key in seen_paths:
                    raise RequestError(
                        HTTPStatus.UNPROCESSABLE_ENTITY,
                        "duplicate_archive_path",
                        "The ZIP archive contains duplicate entry paths.",
                    )
                seen_paths.add(normalized_key)

                entry_mode = (entry.external_attr >> 16) & 0xFFFF
                entry_type = stat.S_IFMT(entry_mode)
                expected_types = {stat.S_IFDIR} if is_directory else {stat.S_IFREG}
                if entry_type and entry_type not in expected_types:
                    raise RequestError(
                        HTTPStatus.UNPROCESSABLE_ENTITY,
                        "unsafe_archive_entry",
                        "The ZIP archive contains a link or unsupported file type.",
                    )
                if entry.file_size < 0:
                    raise RequestError(
                        HTTPStatus.UNPROCESSABLE_ENTITY,
                        "invalid_zip",
                        "The ZIP archive contains an invalid file size.",
                    )
                extracted_total += entry.file_size
                if extracted_total > MAX_EXTRACTED_BYTES:
                    raise RequestError(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        "archive_too_large",
                        "The ZIP archive expands beyond the maximum extracted size.",
                    )
                if is_directory:
                    destination.mkdir(parents=True, exist_ok=True)
                    continue

                destination.parent.mkdir(parents=True, exist_ok=True)
                actual_total = 0
                with archive.open(entry) as source, destination.open("wb") as target:
                    while True:
                        chunk = source.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        actual_total += len(chunk)
                        if actual_total > entry.file_size or actual_total > MAX_EXTRACTED_BYTES:
                            raise RequestError(
                                HTTPStatus.UNPROCESSABLE_ENTITY,
                                "invalid_zip",
                                "A ZIP entry exceeded its declared size.",
                            )
                        target.write(chunk)
                if actual_total != entry.file_size:
                    raise RequestError(
                        HTTPStatus.UNPROCESSABLE_ENTITY,
                        "invalid_zip",
                        "A ZIP entry did not match its declared size.",
                    )
    except RequestError:
        raise
    except (BadZipFile, EOFError, OSError, RuntimeError, NotImplementedError, zlib.error):
        raise RequestError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "invalid_zip",
            "The source ZIP archive could not be safely extracted.",
        ) from None


def _safe_source_path(root: Path, filename: str) -> Path:
    normalized = filename.replace("\\", "/")
    if not normalized or "\x00" in normalized or normalized.startswith("/") or ntpath.splitdrive(normalized)[0]:
        raise RequestError(HTTPStatus.UNPROCESSABLE_ENTITY, "unsafe_source_path", "A source file path is invalid.")
    parts = PurePosixPath(normalized).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise RequestError(HTTPStatus.UNPROCESSABLE_ENTITY, "unsafe_source_path", "A source file path must stay inside the upload.")
    destination = root.joinpath(*parts)
    try:
        destination.resolve().relative_to(root.resolve())
    except ValueError:
        raise RequestError(HTTPStatus.UNPROCESSABLE_ENTITY, "unsafe_source_path", "A source file path is outside the upload.") from None
    return destination


def _write_source_files(root: Path, sources: tuple[UploadedSource, ...]) -> None:
    total = 0
    seen_paths: set[str] = set()
    for source in sources:
        destination = _safe_source_path(root, source.filename)
        normalized_key = destination.relative_to(root).as_posix().casefold()
        if normalized_key in seen_paths:
            raise RequestError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "duplicate_source_path",
                "The source upload contains duplicate file paths.",
            )
        seen_paths.add(normalized_key)
        if destination.suffix.lower() not in ACCEPTED_EXTENSIONS:
            raise RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "unsupported_file_type", "The uploaded file is not a supported source-code format.")
        try:
            source.content.decode("utf-8")
        except UnicodeDecodeError:
            raise RequestError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_source_encoding", "Source files must be valid UTF-8 text.") from None
        total += len(source.content)
        if total > MAX_EXTRACTED_BYTES:
            raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "source_files_too_large", "Source files exceed the configured total size limit.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.content)


def _validate_source_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file() or language_for_path(path) is None:
            continue
        try:
            content = path.read_bytes()
            content.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            raise RequestError(HTTPStatus.UNPROCESSABLE_ENTITY, "binary_source_file", "A supported source file is not valid UTF-8 text.") from None
        if b"\x00" in content:
            raise RequestError(HTTPStatus.UNPROCESSABLE_ENTITY, "binary_source_file", "Binary files are not accepted as source code.")


def _scan_bundle(bundle: UploadBundle, openapi_document: dict[str, Any] | None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="api-intelligence-") as directory:
        root = Path(directory)
        if bundle.source_zip is not None:
            _extract_archive(bundle.source_zip, root)
        else:
            _write_source_files(root, bundle.source_files)
        _validate_source_tree(root)
        security_result = scan_project(root)
        security_findings = to_security_findings(security_result)
        for finding in security_findings:
            file_path = finding.get("file_path")
            if isinstance(file_path, str):
                try:
                    relative_path = Path(file_path).resolve().relative_to(root.resolve())
                except ValueError:
                    continue
                finding["file_path"] = relative_path.as_posix()
        analysis = analyze_project(root, findings=security_findings, openapi_spec=openapi_document)

    return {
        "status": "completed",
        "summary": {
            "routes_discovered": len(analysis["routes"]),
            "security_findings_available": security_result.status.value == "succeeded",
            "security_findings": len(security_findings),
            "analysis_status": security_result.status.value,
            "files_scanned": security_result.files_scanned,
        },
        "routes": analysis["routes"],
        "findings": security_findings,
        "unmatched_findings": analysis["unmatched_findings"],
        "openapi_comparison": analysis["openapi_comparison"],
        "errors": analysis["errors"] + to_security_errors(security_result),
        "limitations": analysis["limitations"],
    }


def _scan(source_zip: bytes, openapi_document: dict[str, Any] | None) -> dict[str, Any]:
    return _scan_bundle(UploadBundle(source_zip=source_zip, source_files=(), openapi_json=None), openapi_document)


def _frontend_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, finding in enumerate(result.get("findings", []), start=1):
        findings.append(
            {
                **finding,
                "id": f"finding-{index}",
                "filePath": finding.get("file_path", ""),
                "status": "Open",
                "mitigation": finding.get("remediation"),
                "source": finding.get("analyzer", "unknown"),
                "language": finding.get("language"),
            }
        )
    return findings


def _frontend_routes(result: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings_by_rule = {finding["rule_id"]: finding["id"] for finding in findings}
    routes: list[dict[str, Any]] = []
    for index, route in enumerate(result.get("routes", []), start=1):
        related = [
            association.get("finding", {})
            for association in route.get("findings", [])
            if isinstance(association, dict)
        ]
        related_ids = [
            findings_by_rule[finding["rule_id"]]
            for finding in related
            if finding.get("rule_id") in findings_by_rule
        ]
        routes.append(
            {
                **route,
                "id": f"route-{index}",
                "filePath": route.get("file", ""),
                "documented": bool(route.get("documented", False)),
                "findings": related_ids,
            }
        )
    return routes


def _store_frontend_scan(result: dict[str, Any]) -> dict[str, Any]:
    global _NEXT_SCAN_ID
    scan_id = f"scan-{_NEXT_SCAN_ID}"
    _NEXT_SCAN_ID += 1
    findings = _frontend_findings(result)
    routes = _frontend_routes(result, findings)
    stored = {**result, "id": scan_id, "findings": findings, "routes": routes}
    _SCAN_RESULTS[scan_id] = stored
    while len(_SCAN_RESULTS) > MAX_STORED_SCANS:
        del _SCAN_RESULTS[next(iter(_SCAN_RESULTS))]
    return {"id": scan_id, "scan_id": scan_id, "status": result["status"]}


def application(environ: dict[str, Any], start_response: Callable[..., Any]) -> list[bytes]:
    """WSGI application for the API Intelligence and frontend scan contracts."""
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "").upper()
    origin = environ.get("HTTP_ORIGIN")
    allowed_origins = {"http://localhost:5173", "http://127.0.0.1:5173"}
    cors_origin = origin if origin in allowed_origins else "http://localhost:5173"
    if path == HEALTH_PATH:
        if method != "GET":
            return _json_response(start_response, HTTPStatus.METHOD_NOT_ALLOWED, {"error": {"kind": "method_not_allowed", "message": "Use GET for this endpoint."}}, cors_origin=cors_origin)
        return _json_response(
            start_response,
            HTTPStatus.OK,
            {"status": "ok", "service": "zeroshadow-api-intelligence"},
            cors_origin=cors_origin,
        )
    if method == "OPTIONS" and (path == ENDPOINT_PATH or path == FRONTEND_SCAN_PATH or path.startswith(FRONTEND_SCANS_PREFIX)):
        return _json_response(start_response, HTTPStatus.NO_CONTENT, {}, cors_origin=cors_origin)
    frontend_scan = path == FRONTEND_SCAN_PATH
    frontend_resource = path.startswith(FRONTEND_SCANS_PREFIX)
    if frontend_resource and method == "GET":
        remainder = path[len(FRONTEND_SCANS_PREFIX):]
        scan_id, _, resource = remainder.partition("/")
        result = _SCAN_RESULTS.get(scan_id)
        if result is None:
            return _json_response(start_response, HTTPStatus.NOT_FOUND, {"error": {"kind": "not_found", "message": "Scan not found."}}, cors_origin=cors_origin)
        if resource == "findings":
            return _json_response(start_response, HTTPStatus.OK, result["findings"], cors_origin=cors_origin)
        if resource == "routes":
            return _json_response(start_response, HTTPStatus.OK, result["routes"], cors_origin=cors_origin)
        if not resource:
            return _json_response(start_response, HTTPStatus.OK, result, cors_origin=cors_origin)
        return _json_response(start_response, HTTPStatus.NOT_FOUND, {"error": {"kind": "not_found", "message": "Scan resource not found."}}, cors_origin=cors_origin)
    if path not in {ENDPOINT_PATH, FRONTEND_SCAN_PATH}:
        return _json_response(
            start_response,
            HTTPStatus.NOT_FOUND,
            {"error": {"kind": "not_found", "message": "Endpoint not found."}},
            cors_origin=cors_origin,
        )
    if method != "POST":
        return _json_response(
            start_response,
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": {"kind": "method_not_allowed", "message": "Use POST for this endpoint."}},
            [("Allow", "POST")],
            cors_origin=cors_origin,
        )

    try:
        body = _read_request_body(environ)
        upload_bundle = _parse_multipart(
            environ.get("CONTENT_TYPE", ""),
            body,
        )
        openapi_document = _validate_openapi(upload_bundle.openapi_json)
        response = _scan_bundle(upload_bundle, openapi_document)
        if frontend_scan:
            response = _store_frontend_scan(response)
    except RequestError as error:
        return _json_response(
            start_response,
            error.status,
            {"error": {"kind": error.kind, "message": error.message}},
            cors_origin=cors_origin,
        )
    except Exception:
        LOGGER.exception("Unexpected API Intelligence scan failure")
        return _json_response(
            start_response,
            HTTPStatus.INTERNAL_SERVER_ERROR,
            {
                "error": {
                    "kind": "scan_failed",
                    "message": "The scan could not be completed.",
                }
            },
            cors_origin=cors_origin,
        )
    return _json_response(start_response, HTTPStatus.OK, response, cors_origin=cors_origin)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    with make_server("127.0.0.1", 8000, application) as server:
        LOGGER.info("API Intelligence endpoint listening on http://127.0.0.1:8000")
        server.serve_forever()
