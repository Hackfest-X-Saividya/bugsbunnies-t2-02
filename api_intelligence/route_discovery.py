"""Discover FastAPI routes and correlate them with existing scanner findings."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
from typing import Any

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
ROUTE_DECORATORS = HTTP_METHODS | {"API_ROUTE"}
SKIPPED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "cache",
    "dist",
    "env",
    "node_modules",
    ".cache",
    ".hypothesis",
    ".nox",
    "venv",
}
AUTH_TOKENS = (
    "auth",
    "authorize",
    "authentication",
    "current_user",
    "jwt",
    "permission",
    "principal",
    "require_user",
    "token",
)


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _read_tree(root: Path) -> tuple[list[tuple[Path, str]], list[dict[str, Any]]]:
    sources: list[tuple[Path, str]] = []
    errors: list[dict[str, Any]] = []

    def on_walk_error(error: OSError) -> None:
        errors.append(
            {
                "file": _relative_path(Path(error.filename or root), root),
                "kind": "read_error",
                "message": f"Unable to enumerate source directory ({type(error).__name__}).",
            }
        )

    for current, directories, filenames in os.walk(root, onerror=on_walk_error):
        directories[:] = sorted(
            name for name in directories if name.lower() not in SKIPPED_DIRECTORIES
        )
        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue
            path = Path(current, filename)
            try:
                sources.append((path, path.read_text(encoding="utf-8")))
            except (OSError, UnicodeError) as error:
                errors.append(
                    {
                        "file": _relative_path(path, root),
                        "kind": "read_error",
                        "message": f"Unable to read source file ({type(error).__name__}).",
                    }
                )
    return sources, errors


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _dependency_expressions(value: ast.expr | None) -> list[ast.expr]:
    if value is None:
        return []
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return list(value.elts)
    return [value]


def _instance_dependencies(tree: ast.Module) -> tuple[dict[str, list[ast.expr]], dict[str, list[ast.expr]]]:
    instances: dict[str, list[ast.expr]] = {}
    included: dict[str, list[ast.expr]] = {}

    for node in ast.walk(tree):
        assigned_name: str | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            if isinstance(node.targets[0], ast.Name):
                assigned_name = node.targets[0].id
                value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            assigned_name = node.target.id
            value = node.value

        if assigned_name is not None and isinstance(value, ast.Call):
            factory = value.func
            if isinstance(factory, ast.Name) and factory.id in {"FastAPI", "APIRouter"}:
                dependencies = _keyword(value, "dependencies")
                if dependencies is not None:
                    instances[assigned_name] = _dependency_expressions(dependencies)

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "include_router"
            and node.args
            and isinstance(node.args[0], ast.Name)
        ):
            application_name = (
                node.func.value.id if isinstance(node.func.value, ast.Name) else None
            )
            dependencies = _keyword(node, "dependencies")
            if dependencies is not None:
                included.setdefault(node.args[0].id, []).extend(
                    _dependency_expressions(dependencies)
                )
            if application_name is not None:
                included.setdefault(node.args[0].id, []).extend(
                    instances.get(application_name, [])
                )
    return instances, included


def _names(expression: ast.AST) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(expression):
        if isinstance(node, ast.Name):
            result.add(node.id.lower())
        elif isinstance(node, ast.Attribute):
            result.add(node.attr.lower())
    return result


def _has_dependency(expression: ast.AST) -> bool:
    for node in ast.walk(expression):
        if isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Name) and function.id in {"Depends", "Security"}:
                return True
            if isinstance(function, ast.Attribute) and function.attr in {"Depends", "Security"}:
                return True
    return False


def _authentication_signal(expressions: list[ast.expr]) -> str:
    if not expressions:
        return "authentication_not_detected_statically"
    if any(_has_dependency(expression) for expression in expressions):
        names = set().union(*(_names(expression) for expression in expressions))
        if any(token in name for name in names for token in AUTH_TOKENS):
            return "authentication_dependency_detected_statically"
    return "authentication_dependency_behavior_unknown"


def _literal_route_path(call: ast.Call) -> str | None:
    candidate: ast.expr | None = call.args[0] if call.args else _keyword(call, "path")
    if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
        return candidate.value
    return None


def _route_methods(call: ast.Call, decorator_name: str) -> list[str] | None:
    if decorator_name != "API_ROUTE":
        return [decorator_name]
    methods = _keyword(call, "methods")
    if methods is None:
        return ["GET"]
    if not isinstance(methods, (ast.List, ast.Tuple, ast.Set)):
        return None
    if any(not isinstance(item, ast.Constant) or not isinstance(item.value, str) for item in methods.elts):
        return None
    return [item.value.upper() for item in methods.elts if item.value.upper() in HTTP_METHODS]


def _route_decorators(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[ast.Call, str]]:
    routes: list[tuple[ast.Call, str]] = []
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        name = decorator.func.attr.upper()
        if name in ROUTE_DECORATORS:
            routes.append((decorator, name))
    return routes


def _handler_dependencies(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.expr]:
    dependencies: list[ast.expr] = []
    for default in function.args.defaults + function.args.kw_defaults:
        if default is not None:
            dependencies.append(default)
    for decorator in function.decorator_list:
        if isinstance(decorator, ast.Call):
            dependencies.extend(_dependency_expressions(_keyword(decorator, "dependencies")))
    return dependencies


def _parse_routes(
    tree: ast.Module,
    relative_file: str,
    authentication_signal: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    instances, included_dependencies = _instance_dependencies(tree)
    routes: list[dict[str, Any]] = []
    limitations: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = _route_decorators(node)
        if not decorators:
            continue

        receiver_names = {
            decorator.func.value.id
            for decorator, _ in decorators
            if isinstance(decorator.func, ast.Attribute)
            and isinstance(decorator.func.value, ast.Name)
        }
        dependencies = _handler_dependencies(node)
        for receiver in receiver_names:
            dependencies.extend(instances.get(receiver, []))
            dependencies.extend(included_dependencies.get(receiver, []))

        signals = [_authentication_signal(dependencies)] if authentication_signal else []
        end_line = getattr(node, "end_lineno", node.lineno)
        start_line = min([node.lineno] + [decorator.lineno for decorator, _ in decorators])

        for decorator, decorator_name in decorators:
            path = _literal_route_path(decorator)
            methods = _route_methods(decorator, decorator_name)
            if path is None or methods is None:
                limitations.append(
                    {
                        "file": relative_file,
                        "line": decorator.lineno,
                        "handler": node.name,
                        "message": "Route path or methods are not statically resolvable.",
                    }
                )
                continue

            for method in methods:
                key = (method, path, node.name, relative_file)
                if key in seen:
                    continue
                seen.add(key)
                routes.append(
                    {
                        "method": method,
                        "path": path,
                        "handler": node.name,
                        "file": relative_file,
                        "line": decorator.lineno,
                        "handler_range": {"start_line": start_line, "end_line": end_line},
                        "security_signals": signals.copy(),
                        "findings": [],
                    }
                )
    routes.sort(key=lambda route: (route["file"], route["line"], route["method"], route["path"]))
    return routes, limitations


def discover_routes(
    project_root: str | os.PathLike[str],
    *,
    authentication_signal: bool = True,
) -> dict[str, Any]:
    """Statically inspect Python files for literal FastAPI route declarations."""
    root = Path(project_root).resolve()
    if not root.exists() or not root.is_dir():
        return {
            "routes": [],
            "errors": [
                {
                    "file": None,
                    "kind": "invalid_project",
                    "message": "Project root does not exist or is not a directory.",
                }
            ],
            "limitations": [],
        }

    sources, errors = _read_tree(root)
    routes: list[dict[str, Any]] = []
    limitations: list[dict[str, Any]] = []
    for path, source in sources:
        relative_file = _relative_path(path, root)
        try:
            tree = ast.parse(source, filename=relative_file)
        except SyntaxError as error:
            errors.append(
                {
                    "file": relative_file,
                    "kind": "syntax_error",
                    "message": f"Unable to parse Python source at line {error.lineno}.",
                }
            )
            continue
        file_routes, file_limitations = _parse_routes(tree, relative_file, authentication_signal)
        routes.extend(file_routes)
        limitations.extend(file_limitations)

    routes.sort(key=lambda route: (route["file"], route["line"], route["method"], route["path"]))
    return {"routes": routes, "errors": errors, "limitations": limitations}


def correlate_findings(
    routes: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Attach defensibly matched findings without changing the source finding records."""
    correlated_routes = [
        {**route, "security_signals": list(route.get("security_signals", [])), "findings": []}
        for route in routes
    ]
    indexes_by_file: dict[str, list[int]] = {}
    for index, route in enumerate(correlated_routes):
        indexes_by_file.setdefault(str(route.get("file", "")), []).append(index)

    unmatched: list[dict[str, Any]] = []
    for finding in findings:
        finding_path = str(finding.get("path", "")).replace("\\", "/")
        line = finding.get("line")
        explicit_handler = next(
            (
                finding[key]
                for key in ("handler", "function", "function_name")
                if isinstance(finding.get(key), str)
            ),
            None,
        )
        matches: list[tuple[int, str]] = []

        if isinstance(line, int):
            for index in indexes_by_file.get(finding_path, []):
                route = correlated_routes[index]
                handler_range = route.get("handler_range", {})
                start = handler_range.get("start_line")
                end = handler_range.get("end_line")
                if isinstance(start, int) and isinstance(end, int) and start <= line <= end:
                    matches.append((index, "handler_range"))

        if not matches and explicit_handler:
            explicit_matches = [
                (index, "handler_match")
                for index, route in enumerate(correlated_routes)
                if route.get("handler") == explicit_handler
                and (not finding_path or route.get("file") == finding_path)
            ]
            if finding_path or len(explicit_matches) == 1:
                matches = explicit_matches

        if not matches and finding_path and len(indexes_by_file.get(finding_path, [])) == 1:
            matches = [(indexes_by_file[finding_path][0], "file_only")]

        if not matches:
            unmatched.append(finding)
            continue

        for index, method in matches:
            associations = correlated_routes[index]["findings"]
            if not any(association["finding"] == finding for association in associations):
                associations.append({"finding": dict(finding), "correlation": method})

    return {"routes": correlated_routes, "unmatched_findings": unmatched}


def _normalize_path(path: str) -> str:
    normalized = "/" + path.strip().strip("/")
    return normalized if normalized != "/" else "/"


def compare_openapi(
    routes: list[dict[str, Any]],
    specification: str | os.PathLike[str] | dict[str, Any],
    *,
    include_documented_only: bool = False,
) -> dict[str, Any]:
    """Compare route method/path pairs to a parsed OpenAPI document or JSON file."""
    try:
        if isinstance(specification, dict):
            document = specification
        else:
            with Path(specification).open("r", encoding="utf-8") as file:
                document = json.load(file)
        if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
            raise ValueError("OpenAPI document must be an object containing a paths object.")
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        return {
            "available": False,
            "error": {
                "kind": "invalid_openapi",
                "message": f"Unable to load a valid OpenAPI document ({type(error).__name__}).",
            },
            "undocumented_routes": [],
            "documented_operations_not_found": [],
        }

    documented: set[tuple[str, str]] = set()
    for path, path_item in document["paths"].items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            continue
        for method in path_item:
            if not isinstance(method, str):
                continue
            upper_method = method.upper()
            if upper_method in HTTP_METHODS:
                documented.add((upper_method, _normalize_path(path)))

    undocumented = [
        {key: route.get(key) for key in ("method", "path", "handler", "file", "line")}
        for route in routes
        if (str(route.get("method", "")).upper(), _normalize_path(str(route.get("path", ""))))
        not in documented
    ]
    not_found: list[dict[str, str]] = []
    if include_documented_only:
        discovered = {
            (str(route.get("method", "")).upper(), _normalize_path(str(route.get("path", ""))))
            for route in routes
        }
        not_found = [
            {"method": method, "path": path}
            for method, path in sorted(documented - discovered)
        ]
    return {
        "available": True,
        "error": None,
        "undocumented_routes": undocumented,
        "documented_operations_not_found": not_found,
    }


def analyze_project(
    project_root: str | os.PathLike[str],
    findings: list[dict[str, Any]] | None = None,
    openapi_spec: str | os.PathLike[str] | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return optional endpoint intelligence without altering a scan-result object."""
    discovery = discover_routes(project_root)
    correlation = correlate_findings(discovery["routes"], findings or [])
    result: dict[str, Any] = {
        "routes": correlation["routes"],
        "unmatched_findings": correlation["unmatched_findings"],
        "errors": discovery["errors"],
        "limitations": discovery["limitations"],
        "openapi_comparison": None,
    }
    if openapi_spec is not None:
        result["openapi_comparison"] = compare_openapi(correlation["routes"], openapi_spec)
    return result
