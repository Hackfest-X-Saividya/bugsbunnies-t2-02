"""Minimal standard-library WSGI endpoint for API Intelligence scans."""

from __future__ import annotations

import io
import json
import logging
import lzma
import ntpath
import os
import re
import stat
import tempfile
import zlib
from email import policy
from email.message import Message
from email.parser import BytesParser
from http import HTTPStatus
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from wsgiref.simple_server import make_server
from zipfile import BadZipFile, ZipFile

from .route_discovery import analyze_project

LOGGER = logging.getLogger(__name__)
ENDPOINT_PATH = "/api/v1/scan"
MAX_REQUEST_BYTES = 20 * 1024 * 1024
MAX_OPENAPI_BYTES = 2 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 5000
MAX_MULTIPART_BOUNDARY_BYTES = 70
BOUNDARY_PATTERN = re.compile(r"[0-9A-Za-z'()+_,./:=?-]+\Z")
CHUNK_SIZE = 64 * 1024


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
) -> list[bytes]:
    encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    start_response(
        f"{status.value} {status.phrase}",
        [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(encoded))),
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


def _parse_multipart(
    content_type: str,
    body: bytes,
) -> tuple[bytes, bytes | None]:
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

    fields: dict[str, bytes] = {}
    filenames: dict[str, str] = {}
    for part in message.iter_parts():
        field_name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        if field_name not in {"source_zip", "openapi_json"} or filename is None:
            raise RequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_form_field",
                "Only source_zip and optional openapi_json file fields are supported.",
            )
        if field_name in fields:
            raise RequestError(
                HTTPStatus.BAD_REQUEST,
                "duplicate_form_field",
                f"The {field_name} field may be supplied only once.",
            )
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            raise RequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_form_field",
                f"The {field_name} upload is invalid.",
            )
        fields[field_name] = payload
        filenames[field_name] = filename

    source_zip = fields.get("source_zip")
    if source_zip is None:
        raise RequestError(
            HTTPStatus.BAD_REQUEST,
            "source_zip_required",
            "A source_zip file upload is required.",
        )
    if Path(filenames["source_zip"]).suffix.lower() != ".zip":
        raise RequestError(
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "unsupported_file_type",
            "The source_zip upload must be a .zip file.",
        )

    openapi_json = fields.get("openapi_json")
    if openapi_json is not None:
        if len(openapi_json) > MAX_OPENAPI_BYTES:
            raise RequestError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "openapi_too_large",
                "The OpenAPI JSON upload exceeds the maximum size.",
            )
        if Path(filenames["openapi_json"]).suffix.lower() != ".json":
            raise RequestError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_file_type",
                "The openapi_json upload must be a .json file.",
            )
    return source_zip, openapi_json


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

    try:
        with archive:
            entries = archive.infolist()
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                raise RequestError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "archive_too_large",
                    "The ZIP archive contains too many entries.",
                )
            extracted_total = 0
            seen_paths: set[str] = set()
            validated_entries: list[tuple[Any, Path, bool]] = []
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
                    if entry.file_size != 0:
                        raise RequestError(
                            HTTPStatus.UNPROCESSABLE_ENTITY,
                            "invalid_zip",
                            "The ZIP archive contains an invalid directory entry.",
                        )
                validated_entries.append((entry, destination, is_directory))

            validated_total = 0
            for entry, _, _ in validated_entries:
                actual_total = 0
                with archive.open(entry) as source:
                    while True:
                        chunk = source.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        actual_total += len(chunk)
                        validated_total += len(chunk)
                        if (
                            actual_total > entry.file_size
                            or validated_total > MAX_EXTRACTED_BYTES
                        ):
                            raise RequestError(
                                HTTPStatus.UNPROCESSABLE_ENTITY,
                                "invalid_zip",
                                "A ZIP entry exceeded its declared size.",
                            )
                if actual_total != entry.file_size:
                    raise RequestError(
                        HTTPStatus.UNPROCESSABLE_ENTITY,
                        "invalid_zip",
                        "A ZIP entry did not match its declared size.",
                    )

            for entry, destination, is_directory in validated_entries:
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
    except (
        BadZipFile,
        EOFError,
        OSError,
        RuntimeError,
        NotImplementedError,
        lzma.LZMAError,
        zlib.error,
    ):
        raise RequestError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "invalid_zip",
            "The source ZIP archive could not be safely extracted.",
        ) from None


def _scan(source_zip: bytes, openapi_document: dict[str, Any] | None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="api-intelligence-") as directory:
        root = Path(directory)
        _extract_archive(source_zip, root)
        analysis = analyze_project(root, openapi_spec=openapi_document)

    return {
        "status": "completed",
        "summary": {
            "routes_discovered": len(analysis["routes"]),
            "security_findings_available": False,
        },
        "routes": analysis["routes"],
        "unmatched_findings": analysis["unmatched_findings"],
        "openapi_comparison": analysis["openapi_comparison"],
        "errors": analysis["errors"],
        "limitations": analysis["limitations"],
    }


def application(environ: dict[str, Any], start_response: Callable[..., Any]) -> list[bytes]:
    """WSGI application implementing POST /api/v1/scan."""
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "").upper()
    if path != ENDPOINT_PATH:
        return _json_response(
            start_response,
            HTTPStatus.NOT_FOUND,
            {"error": {"kind": "not_found", "message": "Endpoint not found."}},
        )
    if method != "POST":
        return _json_response(
            start_response,
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": {"kind": "method_not_allowed", "message": "Use POST for this endpoint."}},
            [("Allow", "POST")],
        )

    try:
        body = _read_request_body(environ)
        source_zip, openapi_bytes = _parse_multipart(
            environ.get("CONTENT_TYPE", ""),
            body,
        )
        openapi_document = _validate_openapi(openapi_bytes)
        response = _scan(source_zip, openapi_document)
    except RequestError as error:
        return _json_response(
            start_response,
            error.status,
            {"error": {"kind": error.kind, "message": error.message}},
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
        )
    return _json_response(start_response, HTTPStatus.OK, response)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    with make_server("127.0.0.1", 8000, application) as server:
        LOGGER.info("API Intelligence endpoint listening on http://127.0.0.1:8000")
        server.serve_forever()
