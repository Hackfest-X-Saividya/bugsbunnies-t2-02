import json
import tempfile
import unittest
from pathlib import Path

from api_intelligence import analyze_project, compare_openapi, correlate_findings, discover_routes


class RouteDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write(self, name, source):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def routes(self, source):
        self.write("app.py", source)
        result = discover_routes(self.root)
        self.assertEqual(result["errors"], [])
        return result["routes"]

    def test_discovers_get_and_post_with_decorator_line_numbers(self):
        routes = self.routes(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/items')\n"
            "def list_items():\n"
            "    return []\n"
            "\n"
            "@app.post('/items')\n"
            "def create_item():\n"
            "    return {}\n"
        )
        self.assertEqual([(route["method"], route["path"]) for route in routes], [
            ("GET", "/items"),
            ("POST", "/items"),
        ])
        self.assertEqual([route["line"] for route in routes], [3, 6])
        self.assertEqual([route["handler"] for route in routes], ["list_items", "create_item"])
        self.assertEqual(routes[0]["file"], "app.py")

    def test_discovers_api_route_methods_and_multiple_decorators(self):
        routes = self.routes(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.api_route('/multi', methods=['get', 'post'])\n"
            "async def multi():\n"
            "    pass\n"
            "@router.get('/same')\n"
            "@router.head('/same')\n"
            "def both():\n"
            "    pass\n"
        )
        self.assertEqual(
            [(route["method"], route["path"]) for route in routes],
            [("GET", "/multi"), ("POST", "/multi"), ("GET", "/same"), ("HEAD", "/same")],
        )
        self.assertEqual([route["line"] for route in routes[2:]], [6, 7])

    def test_discovers_apirouter_and_deduplicates_exact_records(self):
        routes = self.routes(
            "router = APIRouter()\n"
            "@router.patch('/record')\n"
            "@router.patch('/record')\n"
            "def update_record():\n"
            "    pass\n"
        )
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0]["method"], "PATCH")

    def test_reports_syntax_errors_and_missing_project(self):
        self.write("bad.py", "def broken(:\n")
        result = discover_routes(self.root)
        self.assertEqual(result["errors"][0]["kind"], "syntax_error")
        missing = discover_routes(self.root / "missing")
        self.assertEqual(missing["errors"][0]["kind"], "invalid_project")

    def test_reports_unreadable_source_without_stopping_discovery(self):
        (self.root / "unreadable.py").write_bytes(b"\xff")
        self.write("valid.py", "@app.get('/valid')\ndef valid(): pass\n")
        result = discover_routes(self.root)
        self.assertEqual([route["path"] for route in result["routes"]], ["/valid"])
        self.assertEqual(result["errors"][0]["kind"], "read_error")

    def test_skips_virtual_environment_and_cache_directories(self):
        self.write(".venv/lib/site-packages/third_party.py", "@app.get('/ignored')\ndef f(): pass\n")
        self.write("__pycache__/cached.py", "@app.get('/ignored')\ndef f(): pass\n")
        self.assertEqual(discover_routes(self.root)["routes"], [])

    def test_dynamic_route_is_reported_as_limitation(self):
        self.write("app.py", "app = FastAPI()\n@app.get(route_name)\ndef handler(): pass\n")
        result = discover_routes(self.root)
        self.assertEqual(result["routes"], [])
        self.assertEqual(len(result["limitations"]), 1)

    def test_authentication_signals_include_handler_and_router_dependencies(self):
        routes = self.routes(
            "from fastapi import APIRouter, Depends\n"
            "router = APIRouter(dependencies=[Depends(require_auth)])\n"
            "@router.get('/private')\n"
            "def private():\n"
            "    pass\n"
            "@router.get('/unknown')\n"
            "def unknown(user=Depends(load_context)):\n"
            "    pass\n"
            "@router.get('/public')\n"
            "def public():\n"
            "    pass\n"
        )
        signals = {route["path"]: route["security_signals"][0] for route in routes}
        self.assertEqual(signals["/private"], "authentication_dependency_detected_statically")
        self.assertEqual(signals["/unknown"], "authentication_dependency_detected_statically")
        self.assertEqual(signals["/public"], "authentication_dependency_detected_statically")

    def test_detects_application_level_dependency_included_by_router(self):
        routes = self.routes(
            "from fastapi import APIRouter, Depends, FastAPI\n"
            "app = FastAPI(dependencies=[Depends(require_auth)])\n"
            "router = APIRouter()\n"
            "@router.get('/included')\n"
            "def included(): pass\n"
            "app.include_router(router)\n"
        )
        self.assertEqual(
            routes[0]["security_signals"],
            ["authentication_dependency_detected_statically"],
        )

    def test_unknown_dependency_and_no_dependency_signals(self):
        routes = self.routes(
            "from fastapi import FastAPI, Depends\n"
            "app = FastAPI()\n"
            "@app.get('/unknown')\n"
            "def unknown(value=Depends(load_context)): pass\n"
            "@app.get('/none')\n"
            "def none(): pass\n"
        )
        signals = {route["path"]: route["security_signals"][0] for route in routes}
        self.assertEqual(signals["/unknown"], "authentication_dependency_behavior_unknown")
        self.assertEqual(signals["/none"], "authentication_not_detected_statically")

    def test_correlates_range_file_only_and_unmatched_findings(self):
        routes = [
            {
                "method": "GET",
                "path": "/one",
                "handler": "one",
                "file": "routes.py",
                "line": 1,
                "handler_range": {"start_line": 1, "end_line": 5},
                "security_signals": [],
                "findings": [],
            },
            {
                "method": "POST",
                "path": "/two",
                "handler": "two",
                "file": "routes.py",
                "line": 10,
                "handler_range": {"start_line": 10, "end_line": 15},
                "security_signals": [],
                "findings": [],
            },
            {
                "method": "GET",
                "path": "/single",
                "handler": "single",
                "file": "single.py",
                "line": 2,
                "handler_range": {"start_line": 2, "end_line": 4},
                "security_signals": [],
                "findings": [],
            },
        ]
        original = {"rule_id": "B101", "path": "routes.py", "line": 4, "evidence": "assert x"}
        outside = {"rule_id": "B102", "path": "routes.py", "line": 8}
        file_only = {"rule_id": "B103", "path": "single.py", "line": None}
        unmatched = {"rule_id": "B104", "path": "elsewhere.py", "line": 3}
        result = correlate_findings(routes, [original, outside, file_only, unmatched])
        self.assertEqual(result["routes"][0]["findings"][0]["correlation"], "handler_range")
        self.assertEqual(result["routes"][2]["findings"][0]["correlation"], "file_only")
        self.assertEqual(result["unmatched_findings"], [outside, unmatched])
        self.assertEqual(result["routes"][0]["findings"][0]["finding"], original)
        self.assertEqual(routes[0]["findings"], [])

    def test_deduplicates_repeated_finding_associations(self):
        route = {
            "handler": "target",
            "file": "target.py",
            "handler_range": {"start_line": 1, "end_line": 3},
            "findings": [],
            "security_signals": [],
        }
        finding = {"path": "target.py", "line": 2, "rule_id": "B101"}
        result = correlate_findings([route], [finding, finding.copy()])
        self.assertEqual(len(result["routes"][0]["findings"]), 1)

    def test_does_not_associate_file_level_finding_with_every_endpoint(self):
        routes = [
            {"handler": "first", "file": "many.py", "findings": [], "security_signals": []},
            {"handler": "second", "file": "many.py", "findings": [], "security_signals": []},
        ]
        finding = {"path": "many.py", "line": None}
        result = correlate_findings(routes, [finding])
        self.assertEqual([route["findings"] for route in result["routes"]], [[], []])
        self.assertEqual(result["unmatched_findings"], [finding])

    def test_correlates_explicit_handler_match(self):
        route = {
            "handler": "target",
            "file": "target.py",
            "findings": [],
            "security_signals": [],
        }
        finding = {"path": "target.py", "function_name": "target", "line": None}
        result = correlate_findings([route], [finding])
        self.assertEqual(result["routes"][0]["findings"][0]["correlation"], "handler_match")

    def test_openapi_comparison_and_optional_documented_only_results(self):
        routes = [
            {"method": "GET", "path": "/items/", "handler": "items", "file": "app.py", "line": 2},
            {"method": "POST", "path": "/hidden", "handler": "hidden", "file": "app.py", "line": 5},
        ]
        spec = {"paths": {"/items": {"get": {}}, "/missing": {"post": {}}}}
        result = compare_openapi(routes, spec, include_documented_only=True)
        self.assertTrue(result["available"])
        self.assertEqual([item["path"] for item in result["undocumented_routes"]], ["/hidden"])
        self.assertEqual(result["documented_operations_not_found"], [{"method": "POST", "path": "/missing"}])

    def test_openapi_json_file_and_malformed_documents(self):
        routes = [{"method": "GET", "path": "/", "handler": "root", "file": "app.py", "line": 1}]
        specification = self.root / "openapi.json"
        specification.write_text(json.dumps({"paths": {"/": {"get": {}}}}), encoding="utf-8")
        self.assertTrue(compare_openapi(routes, specification)["available"])
        invalid = self.root / "invalid.json"
        invalid.write_text("{", encoding="utf-8")
        self.assertFalse(compare_openapi(routes, invalid)["available"])
        self.assertFalse(compare_openapi(routes, {})["available"])
        self.assertTrue(compare_openapi(routes, {"paths": {"/": {None: {}}}})["available"])

    def test_preserves_scan_result_and_exposes_intelligence_separately(self):
        self.write(
            "app.py",
            "from fastapi import FastAPI\napp = FastAPI()\n"
            "@app.get('/items')\ndef items():\n    return []\n",
        )
        scan_result = {
            "status": "succeeded",
            "findings": [{"rule_id": "B105", "path": "app.py", "line": 5}],
            "errors": [],
            "exit_code": 1,
            "duration_ms": 10,
            "files_scanned": 1,
        }
        original = json.loads(json.dumps(scan_result))
        intelligence = analyze_project(self.root, scan_result["findings"])
        self.assertEqual(scan_result, original)
        self.assertEqual(intelligence["routes"][0]["findings"][0]["correlation"], "handler_range")


if __name__ == "__main__":
    unittest.main()
