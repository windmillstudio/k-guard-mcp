from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
STAGER_PATH = REPOSITORY_ROOT / "scripts" / "stage_l3_generated_pair_source_triplets.py"
SCHEMA_V1 = "k_guard_l3_source_flow_slot_materialization.v1"
VERSION_V1 = "1.0.0"
SCHEMA = "k_guard_l3_source_flow_slot_materialization.v2"
VERSION = "2.0.0"
MATERIALIZER_IDENTITY_SCHEMA = "k_guard_l3_source_flow_slot_materializer_identity.v1"
MATERIALIZATION_CONTRACT_VERSION = "1.0.0"
TRIPLET_STATES = ("vulnerable", "fixed", "negative")
LICENSE_SPDX = "MIT"
LICENSE_TEXT = """MIT License

Copyright (c) 2026 K-Guard generated development corpus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

CLAIM_BOUNDARY = {
    "materialized_slot_count": 1,
    "materialized_candidate_count": 2,
    "source_triplets_materialized": True,
    "execution_oracles_proved": False,
    "scanner_output_observed": False,
    "eligible_for_tp_fp_fn": False,
    "eligible_for_h100": False,
    "release_gate_passed": False,
    "raw_source_returned": False,
}

# These exact v1 hashes are the only legacy provenance values that may be
# replayed.  A v1 receipt must still satisfy today's staged-input, candidate,
# root-binding, and byte-for-byte source-tree checks.
LEGACY_WHOLE_MODULE_SHA256_BY_SLOT: dict[str, frozenset[str]] = {
    "site-15": frozenset({"7e769360f5f78303c52874949918779bb67932b65c9fc65e0870f89d282d8f4f"}),
    "data-03": frozenset({"eed7f75aecd5a9e94aabf76062092b2d8a09f32d893c67b922dbc92f017b48c8"}),
}

# This contract version is intentionally independent of the set of supported
# slots.  Bump it when shared materialization or validation semantics change.
RENDERER_CONTRACT_VERSIONS = {
    "express-sql-query.v1": "1.0.0",
    "go-chi-sql-builder.v1": "1.0.0",
    "typescript-prisma-raw-query.v1": "1.0.0",
    "python-fastapi-parameterized-query.v1": "1.0.0",
    "java-spring-jdbc-concat.v1": "1.0.0",
    "go-pgx-query-format.v1": "1.0.0",
}

# A config must be added deliberately for every new leaf. Unsupported slots never fall back.
SLOT_CONFIGS: dict[str, dict[str, Any]] = {
    "site-02": {
        "expected": {
            "scenario_id": "dev-site-02-sqli-query",
            "oracle_id": "l3-gen-site-02-sqli-query",
            "plane": "site",
            "family": "source-flow",
            "language": "javascript",
            "framework": "express",
            "coverage_tags": ["express"],
            "cwe": "CWE-89",
            "severity": "high",
            "generator_profile": "deterministic-template-v1",
        },
        "renderer": "express-sql-query.v1",
        "candidates": {
            0: {
                "template_id": "source-flow-site-02-primary-v1",
                "function_name": "findAccountByEmail",
                "input_name": "email",
                "route_path": "routes/account.js",
                "static_value": "active",
            },
            1: {
                "template_id": "source-flow-site-02-reserve-v1",
                "function_name": "findInvoiceByReference",
                "input_name": "reference",
                "route_path": "routes/invoice.js",
                "static_value": "issued",
            },
        },
    },
    "site-15": {
        "expected": {
            "scenario_id": "dev-site-15-sql-builder",
            "oracle_id": "l3-gen-site-15-sql-builder",
            "plane": "site",
            "family": "source-flow",
            "language": "go",
            "framework": "chi",
            "coverage_tags": ["express"],
            "cwe": "CWE-89",
            "severity": "critical",
            "generator_profile": "deterministic-transform-v1",
        },
        "renderer": "go-chi-sql-builder.v1",
        "candidates": {
            0: {
                "template_id": "source-flow-site-15-primary-sql-builder-template-v1",
                "source_path": "internal/checkout/orders.go",
                "package_name": "checkout",
                "handler_name": "orderLookup",
                "route_path": "/orders",
                "parameter_name": "id",
                "table_name": "orders",
                "result_column": "status",
                "static_message": "orders-ready",
            },
            1: {
                "template_id": "source-flow-site-15-reserve-sql-builder-template-v1",
                "source_path": "internal/integrations/providers.go",
                "package_name": "integrations",
                "handler_name": "providerLookup",
                "route_path": "/integrations",
                "parameter_name": "provider",
                "table_name": "integrations",
                "result_column": "endpoint",
                "static_message": "integrations-ready",
            },
        },
    },
    "data-03": {
        "expected": {
            "scenario_id": "dev-data-03-raw-query",
            "oracle_id": "l3-gen-data-03-raw-query",
            "plane": "data",
            "family": "source-flow",
            "language": "typescript",
            "framework": "prisma",
            "coverage_tags": ["sql-rls"],
            "cwe": "CWE-89",
            "severity": "high",
            "generator_profile": "deterministic-transform-v1",
        },
        "renderer": "typescript-prisma-raw-query.v1",
        "candidates": {
            0: {
                "template_id": "source-flow-data-03-primary-prisma-raw-query-template-v1",
                "source_path": "src/data/checkout/orders.ts",
                "function_name": "findOrderById",
                "parameter_name": "id",
                "table_name": "orders",
                "result_column": "status",
                "static_message": "orders-ready",
            },
            1: {
                "template_id": "source-flow-data-03-reserve-prisma-raw-query-template-v1",
                "source_path": "src/data/integrations/providers.ts",
                "function_name": "findProviderBySlug",
                "parameter_name": "provider",
                "table_name": "integrations",
                "result_column": "endpoint",
                "static_message": "integrations-ready",
            },
        },
    },
    "data-07": {
        "expected": {
            "scenario_id": "dev-data-07-parameterized-query",
            "oracle_id": "l3-gen-data-07-parameterized-query",
            "plane": "data",
            "family": "source-flow",
            "language": "python",
            "framework": "fastapi",
            "coverage_tags": ["sql-rls"],
            "cwe": "CWE-89",
            "severity": "high",
            "generator_profile": "deterministic-fixture-v1",
        },
        "renderer": "python-fastapi-parameterized-query.v1",
        "candidates": {
            0: {
                "template_id": "source-flow-data-07-primary-fastapi-parameterized-query-template-v1",
                "source_path": "app/api/checkout/orders.py",
                "function_name": "get_order_by_id",
                "route_path": "/orders/{order_id}",
                "negative_route_path": "/orders",
                "parameter_name": "order_id",
                "lookup_column": "id",
                "table_name": "orders",
                "result_column": "status",
                "static_message": "orders-ready",
            },
            1: {
                "template_id": "source-flow-data-07-reserve-fastapi-parameterized-query-template-v1",
                "source_path": "app/api/integrations/providers.py",
                "function_name": "get_provider_by_slug",
                "route_path": "/integrations/{provider}",
                "negative_route_path": "/integrations",
                "parameter_name": "provider",
                "lookup_column": "slug",
                "table_name": "integrations",
                "result_column": "endpoint",
                "static_message": "integrations-ready",
            },
        },
    },
    "data-09": {
        "expected": {
            "scenario_id": "dev-data-09-jdbc-concat",
            "oracle_id": "l3-gen-data-09-jdbc-concat",
            "plane": "data",
            "family": "source-flow",
            "language": "java",
            "framework": "spring",
            "coverage_tags": ["sql-rls"],
            "cwe": "CWE-89",
            "severity": "high",
            "generator_profile": "deterministic-transform-v1",
        },
        "renderer": "java-spring-jdbc-concat.v1",
        "candidates": {
            0: {
                "template_id": "source-flow-data-09-primary-spring-jdbc-concat-template-v1",
                "source_path": "src/main/java/com/kguard/checkout/OrdersController.java",
                "package_name": "com.kguard.checkout",
                "class_name": "OrdersController",
                "function_name": "findOrderById",
                "route_path": "/orders/{id}",
                "negative_route_path": "/orders",
                "parameter_name": "id",
                "lookup_column": "id",
                "table_name": "orders",
                "result_column": "status",
                "static_message": "orders-ready",
            },
            1: {
                "template_id": "source-flow-data-09-reserve-spring-jdbc-concat-template-v1",
                "source_path": "src/main/java/com/kguard/integrations/ProvidersController.java",
                "package_name": "com.kguard.integrations",
                "class_name": "ProvidersController",
                "function_name": "findProviderBySlug",
                "route_path": "/integrations/{provider}",
                "negative_route_path": "/integrations",
                "parameter_name": "provider",
                "lookup_column": "slug",
                "table_name": "integrations",
                "result_column": "endpoint",
                "static_message": "integrations-ready",
            },
        },
    },
    "data-14": {
        "expected": {
            "scenario_id": "dev-data-14-query-format",
            "oracle_id": "l3-gen-data-14-query-format",
            "plane": "data",
            "family": "source-flow",
            "language": "go",
            "framework": "pgx",
            "coverage_tags": ["sql-rls"],
            "cwe": "CWE-89",
            "severity": "high",
            "generator_profile": "deterministic-template-v1",
        },
        "renderer": "go-pgx-query-format.v1",
        "candidates": {
            0: {
                "template_id": "source-flow-data-14-primary-pgx-query-format-template-v1",
                "source_path": "internal/checkout/invoices.go",
                "package_name": "checkout",
                "function_name": "FindInvoiceByNumber",
                "route_path": "/invoices/{number}",
                "negative_route_path": "/invoices",
                "parameter_name": "number",
                "lookup_column": "number",
                "table_name": "invoices",
                "result_column": "amount",
                "static_message": "invoices-ready",
            },
            1: {
                "template_id": "source-flow-data-14-reserve-pgx-query-format-template-v1",
                "source_path": "internal/catalog/products.go",
                "package_name": "catalog",
                "function_name": "FindProductBySKU",
                "route_path": "/products/{sku}",
                "negative_route_path": "/products",
                "parameter_name": "sku",
                "lookup_column": "sku",
                "table_name": "products",
                "result_column": "price",
                "static_message": "products-ready",
            },
        },
    },
}


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def _domain_hash(domain: bytes, value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return hashlib.sha256(domain + encoded).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _slot_definition_sha256(slot_id: str) -> str:
    return _domain_hash(b"k_guard_l3_source_flow_slot_definition.v1\0", _slot_config(slot_id))


def _reject_duplicate_keys(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("source_flow_slot_duplicate_json_key")
        result[key] = item
    return result


def _is_within_repository(path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve(strict=True))
        return True
    except ValueError:
        return False


def _require_external_path(path: Path, error: str) -> None:
    if not path.is_absolute() or _is_within_repository(path):
        raise ValueError(error)


def _paths_overlap(first: Path, second: Path) -> bool:
    first_resolved = first.resolve(strict=False)
    second_resolved = second.resolve(strict=False)
    try:
        first_resolved.relative_to(second_resolved)
        return True
    except ValueError:
        pass
    try:
        second_resolved.relative_to(first_resolved)
        return True
    except ValueError:
        return False


def _slot_config(slot_id: str) -> dict[str, Any]:
    try:
        return SLOT_CONFIGS[slot_id]
    except KeyError as exc:
        raise ValueError("source_flow_slot_not_preregistered") from exc


def _load_stager() -> tuple[Any, str]:
    raw_before = STAGER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l3_stager_for_source_flow_slot", STAGER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("source_flow_slot_stager_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if STAGER_PATH.read_bytes() != raw_before:
        raise ValueError("source_flow_slot_stager_changed_while_loading")
    return module, _sha256_bytes(raw_before)


def _load_staging_inputs(
    blueprint_path: Path,
    staging_receipt_path: Path,
    staging_root: Path,
) -> tuple[dict[str, Any], str, str]:
    for path, error in (
        (blueprint_path, "source_flow_slot_blueprint_must_be_external"),
        (staging_receipt_path, "source_flow_slot_staging_receipt_must_be_external"),
        (staging_root, "source_flow_slot_staging_root_must_be_external"),
    ):
        _require_external_path(path, error)
    if not staging_receipt_path.is_file() or staging_receipt_path.is_symlink():
        raise ValueError("source_flow_slot_staging_receipt_path_invalid")
    stager, stager_sha256 = _load_stager()
    raw_before = staging_receipt_path.read_bytes()
    receipt = stager.load_staging_receipt(staging_receipt_path, blueprint_path, staging_root)
    if staging_receipt_path.read_bytes() != raw_before:
        raise ValueError("source_flow_slot_staging_receipt_changed_while_loading")
    return receipt, _sha256_bytes(raw_before), stager_sha256


def _slot_candidates(staging_receipt: Mapping[str, Any], slot_id: str) -> list[dict[str, Any]]:
    config = _slot_config(slot_id)
    candidates = [dict(candidate) for candidate in staging_receipt["candidates"] if candidate["slot_id"] == slot_id]
    if len(candidates) != 2 or [candidate["candidate_rank"] for candidate in candidates] != [0, 1]:
        raise ValueError("source_flow_slot_candidate_set_invalid")
    expected = {"slot_id": slot_id, **config["expected"]}
    for candidate in candidates:
        for key, value in expected.items():
            if candidate.get(key) != value:
                raise ValueError("source_flow_slot_candidate_binding_invalid")
        rank = candidate["candidate_rank"]
        if candidate.get("candidate_role") != ("primary" if rank == 0 else "reserve"):
            raise ValueError("source_flow_slot_candidate_role_invalid")
        expected_root = f"slots/{slot_id}/candidate-{rank}"
        if candidate.get("candidate_relative_root") != expected_root:
            raise ValueError("source_flow_slot_candidate_path_invalid")
        expected_triplets = {state: f"{expected_root}/{state}" for state in TRIPLET_STATES}
        if candidate.get("triplet_relative_paths") != expected_triplets:
            raise ValueError("source_flow_slot_triplet_path_invalid")
    return candidates


def _candidate_spec(slot_id: str, candidate_rank: int) -> dict[str, str]:
    config = _slot_config(slot_id)
    candidates = config["candidates"]
    try:
        value = candidates[candidate_rank]
    except KeyError as exc:
        raise ValueError("source_flow_slot_candidate_rank_invalid") from exc
    required_keys_by_renderer = {
        "express-sql-query.v1": {
            "template_id", "function_name", "input_name", "route_path", "static_value"
        },
        "go-chi-sql-builder.v1": {
            "template_id", "source_path", "package_name", "handler_name", "route_path",
            "parameter_name", "table_name", "result_column", "static_message",
        },
            "typescript-prisma-raw-query.v1": {
                "template_id", "source_path", "function_name", "parameter_name", "table_name",
                "result_column", "static_message",
            },
            "python-fastapi-parameterized-query.v1": {
                "template_id", "source_path", "function_name", "route_path", "negative_route_path",
                "parameter_name", "lookup_column", "table_name", "result_column", "static_message",
            },
            "java-spring-jdbc-concat.v1": {
                "template_id", "source_path", "package_name", "class_name", "function_name", "route_path",
                "negative_route_path", "parameter_name", "lookup_column", "table_name", "result_column",
                "static_message",
            },
            "go-pgx-query-format.v1": {
                "template_id", "source_path", "package_name", "function_name", "route_path",
                "negative_route_path", "parameter_name", "lookup_column", "table_name", "result_column",
                "static_message",
            },
        }
    try:
        required_keys = required_keys_by_renderer[config["renderer"]]
    except KeyError as exc:
        raise ValueError("source_flow_slot_renderer_invalid") from exc
    if not isinstance(value, dict) or set(value) != required_keys:
        raise ValueError("source_flow_slot_candidate_spec_invalid")
    return dict(value)


def _route_source(spec: Mapping[str, str], state: str) -> bytes:
    function_name = spec["function_name"]
    input_name = spec["input_name"]
    if state == "vulnerable":
        query = f"const sql = \"SELECT id FROM records WHERE value = '\" + {input_name} + \"'\";\n  return db.query(sql);"
    elif state == "fixed":
        query = f"return db.query(\"SELECT id FROM records WHERE value = ?\", [{input_name}]);"
    elif state == "negative":
        query = f"return db.query(\"SELECT id FROM records WHERE state = ?\", [\"{spec['static_value']}\"]);"
    else:
        raise ValueError("source_flow_slot_tree_state_invalid")
    return (
        f"export function {function_name}(req, res, db) {{\n"
        f"  const {input_name} = req.query.{input_name};\n"
        f"  {query}\n"
        "}\n"
    ).encode("ascii")


def _go_chi_sql_builder_source(spec: Mapping[str, str], state: str) -> bytes:
    package_name = spec["package_name"]
    handler_name = spec["handler_name"]
    route_path = spec["route_path"]
    parameter_name = spec["parameter_name"]
    table_name = spec["table_name"]
    result_column = spec["result_column"]
    static_message = spec["static_message"]
    register_name = f"Register{handler_name[0].upper()}{handler_name[1:]}"
    if state == "vulnerable":
        body = (
            f"package {package_name}\n\n"
            "import (\n"
            "\t\"database/sql\"\n"
            "\t\"fmt\"\n"
            "\t\"net/http\"\n\n"
            "\t\"github.com/go-chi/chi/v5\"\n"
            ")\n\n"
            f"func {register_name}(router chi.Router, db *sql.DB) {{\n"
            f"\trouter.Get({json.dumps(route_path, ensure_ascii=True)}, {handler_name}(db))\n"
            "}\n\n"
            f"func {handler_name}(db *sql.DB) http.HandlerFunc {{\n"
            "\treturn func(w http.ResponseWriter, r *http.Request) {\n"
            f"\t\t{parameter_name} := r.URL.Query().Get({json.dumps(parameter_name, ensure_ascii=True)})\n"
            f"\t\tquery := fmt.Sprintf(\"SELECT {result_column} FROM {table_name} WHERE {parameter_name} = '%s'\", {parameter_name})\n"
            "\t\trow := db.QueryRowContext(r.Context(), query)\n"
            "\t\t_ = row\n"
            f"\t\t_, _ = w.Write([]byte({json.dumps(static_message, ensure_ascii=True)}))\n"
            "\t}\n"
            "}\n"
        )
    elif state == "fixed":
        body = (
            f"package {package_name}\n\n"
            "import (\n"
            "\t\"database/sql\"\n"
            "\t\"net/http\"\n\n"
            "\t\"github.com/go-chi/chi/v5\"\n"
            ")\n\n"
            f"func {register_name}(router chi.Router, db *sql.DB) {{\n"
            f"\trouter.Get({json.dumps(route_path, ensure_ascii=True)}, {handler_name}(db))\n"
            "}\n\n"
            f"func {handler_name}(db *sql.DB) http.HandlerFunc {{\n"
            "\treturn func(w http.ResponseWriter, r *http.Request) {\n"
            f"\t\t{parameter_name} := r.URL.Query().Get({json.dumps(parameter_name, ensure_ascii=True)})\n"
            f"\t\tconst query = \"SELECT {result_column} FROM {table_name} WHERE {parameter_name} = ?\"\n"
            f"\t\trow := db.QueryRowContext(r.Context(), query, {parameter_name})\n"
            "\t\t_ = row\n"
            f"\t\t_, _ = w.Write([]byte({json.dumps(static_message, ensure_ascii=True)}))\n"
            "\t}\n"
            "}\n"
        )
    elif state == "negative":
        body = (
            f"package {package_name}\n\n"
            "import (\n"
            "\t\"net/http\"\n\n"
            "\t\"github.com/go-chi/chi/v5\"\n"
            ")\n\n"
            f"func {register_name}(router chi.Router) {{\n"
            f"\trouter.Get({json.dumps(route_path, ensure_ascii=True)}, {handler_name}())\n"
            "}\n\n"
            f"func {handler_name}() http.HandlerFunc {{\n"
            "\treturn func(w http.ResponseWriter, _ *http.Request) {\n"
            f"\t\t_, _ = w.Write([]byte({json.dumps(static_message, ensure_ascii=True)}))\n"
            "\t}\n"
            "}\n"
        )
    else:
        raise ValueError("source_flow_slot_tree_state_invalid")
    return body.encode("ascii")


def _go_pgx_query_format_source(spec: Mapping[str, str], state: str) -> bytes:
    package_name = spec["package_name"]
    function_name = spec["function_name"]
    route_path = spec["route_path"]
    negative_route_path = spec["negative_route_path"]
    parameter_name = spec["parameter_name"]
    lookup_column = spec["lookup_column"]
    table_name = spec["table_name"]
    result_column = spec["result_column"]
    static_message = spec["static_message"]
    register_name = f"Register{function_name}"
    if state == "vulnerable":
        body = (
            f"package {package_name}\n\n"
            "import (\n"
            "\t\"fmt\"\n"
            "\t\"net/http\"\n\n"
            "\t\"github.com/jackc/pgx/v5/pgxpool\"\n"
            ")\n\n"
            f"func {register_name}(mux *http.ServeMux, pool *pgxpool.Pool) {{\n"
            f"\tmux.HandleFunc({json.dumps(route_path, ensure_ascii=True)}, {function_name}(pool))\n"
            "}\n\n"
            f"func {function_name}(pool *pgxpool.Pool) http.HandlerFunc {{\n"
            "\treturn func(w http.ResponseWriter, r *http.Request) {\n"
            f"\t\t{parameter_name} := r.PathValue({json.dumps(parameter_name, ensure_ascii=True)})\n"
            f"\t\tquery := fmt.Sprintf(\"SELECT {result_column} FROM {table_name} WHERE {lookup_column} = '%s'\", {parameter_name})\n"
            "\t\trow := pool.QueryRow(r.Context(), query)\n"
            "\t\t_ = row\n"
            f"\t\t_, _ = w.Write([]byte({json.dumps(static_message, ensure_ascii=True)}))\n"
            "\t}\n"
            "}\n"
        )
    elif state == "fixed":
        body = (
            f"package {package_name}\n\n"
            "import (\n"
            "\t\"net/http\"\n\n"
            "\t\"github.com/jackc/pgx/v5/pgxpool\"\n"
            ")\n\n"
            f"func {register_name}(mux *http.ServeMux, pool *pgxpool.Pool) {{\n"
            f"\tmux.HandleFunc({json.dumps(route_path, ensure_ascii=True)}, {function_name}(pool))\n"
            "}\n\n"
            f"func {function_name}(pool *pgxpool.Pool) http.HandlerFunc {{\n"
            "\treturn func(w http.ResponseWriter, r *http.Request) {\n"
            f"\t\t{parameter_name} := r.PathValue({json.dumps(parameter_name, ensure_ascii=True)})\n"
            f"\t\tconst query = \"SELECT {result_column} FROM {table_name} WHERE {lookup_column} = $1\"\n"
            f"\t\trow := pool.QueryRow(r.Context(), query, {parameter_name})\n"
            "\t\t_ = row\n"
            f"\t\t_, _ = w.Write([]byte({json.dumps(static_message, ensure_ascii=True)}))\n"
            "\t}\n"
            "}\n"
        )
    elif state == "negative":
        body = (
            f"package {package_name}\n\n"
            "import \"net/http\"\n\n"
            f"func {register_name}(mux *http.ServeMux) {{\n"
            f"\tmux.HandleFunc({json.dumps(negative_route_path, ensure_ascii=True)}, {function_name}())\n"
            "}\n\n"
            f"func {function_name}() http.HandlerFunc {{\n"
            "\treturn func(w http.ResponseWriter, _ *http.Request) {\n"
            f"\t\t_, _ = w.Write([]byte({json.dumps(static_message, ensure_ascii=True)}))\n"
            "\t}\n"
            "}\n"
        )
    else:
        raise ValueError("source_flow_slot_tree_state_invalid")
    return body.encode("ascii")


def _typescript_prisma_raw_query_source(spec: Mapping[str, str], state: str) -> bytes:
    function_name = spec["function_name"]
    parameter_name = spec["parameter_name"]
    table_name = spec["table_name"]
    result_column = spec["result_column"]
    static_message = spec["static_message"]
    interpolation = "${" + parameter_name + "}"
    if state == "vulnerable":
        body = (
            'import { PrismaClient } from "@prisma/client";\n\n'
            f"export async function {function_name}(prisma: PrismaClient, {parameter_name}: string) {{\n"
            f"  const query = `SELECT {result_column} FROM {table_name} WHERE {parameter_name} = '{interpolation}'`;\n"
            "  return prisma.$queryRawUnsafe(query);\n"
            "}\n"
        )
    elif state == "fixed":
        body = (
            'import { Prisma, PrismaClient } from "@prisma/client";\n\n'
            f"export async function {function_name}(prisma: PrismaClient, {parameter_name}: string) {{\n"
            f"  const query = Prisma.sql`SELECT {result_column} FROM {table_name} WHERE {parameter_name} = {interpolation}`;\n"
            "  return prisma.$queryRaw(query);\n"
            "}\n"
        )
    elif state == "negative":
        body = (
            f"export function {function_name}() {{\n"
            f"  return {json.dumps(static_message, ensure_ascii=True)};\n"
            "}\n"
        )
    else:
        raise ValueError("source_flow_slot_tree_state_invalid")
    return body.encode("ascii")


def _fastapi_parameterized_query_source(spec: Mapping[str, str], state: str) -> bytes:
    function_name = spec["function_name"]
    route_path = spec["route_path"]
    negative_route_path = spec["negative_route_path"]
    parameter_name = spec["parameter_name"]
    lookup_column = spec["lookup_column"]
    table_name = spec["table_name"]
    result_column = spec["result_column"]
    static_message = spec["static_message"]
    if state == "vulnerable":
        body = (
            "import sqlite3\n\n"
            "from fastapi import FastAPI\n\n"
            "app = FastAPI()\n"
            "connection = sqlite3.connect(\":memory:\")\n\n"
            f"@app.get({json.dumps(route_path, ensure_ascii=True)})\n"
            f"def {function_name}({parameter_name}: str):\n"
            f'    query = f"SELECT {result_column} FROM {table_name} WHERE {lookup_column} = \'{{{parameter_name}}}\'"\n'
            "    return connection.execute(query).fetchone()\n"
        )
    elif state == "fixed":
        body = (
            "import sqlite3\n\n"
            "from fastapi import FastAPI\n\n"
            "app = FastAPI()\n"
            "connection = sqlite3.connect(\":memory:\")\n\n"
            f"@app.get({json.dumps(route_path, ensure_ascii=True)})\n"
            f"def {function_name}({parameter_name}: str):\n"
            f'    query = "SELECT {result_column} FROM {table_name} WHERE {lookup_column} = ?"\n'
            f"    return connection.execute(query, ({parameter_name},)).fetchone()\n"
        )
    elif state == "negative":
        body = (
            "from fastapi import FastAPI\n"
            "from fastapi.responses import JSONResponse\n\n"
            "app = FastAPI()\n\n"
            f"@app.get({json.dumps(negative_route_path, ensure_ascii=True)})\n"
            f"def {function_name}():\n"
            f"    return JSONResponse({{{json.dumps(result_column, ensure_ascii=True)}: {json.dumps(static_message, ensure_ascii=True)}}})\n"
        )
    else:
        raise ValueError("source_flow_slot_tree_state_invalid")
    return body.encode("ascii")


def _java_spring_jdbc_concat_source(spec: Mapping[str, str], state: str) -> bytes:
    package_name = spec["package_name"]
    class_name = spec["class_name"]
    function_name = spec["function_name"]
    route_path = spec["route_path"]
    negative_route_path = spec["negative_route_path"]
    parameter_name = spec["parameter_name"]
    lookup_column = spec["lookup_column"]
    table_name = spec["table_name"]
    result_column = spec["result_column"]
    static_message = spec["static_message"]
    if state == "vulnerable":
        body = (
            f"package {package_name};\n\n"
            "import java.sql.Connection;\n"
            "import java.sql.ResultSet;\n"
            "import java.sql.SQLException;\n"
            "import java.sql.Statement;\n\n"
            "import org.springframework.web.bind.annotation.GetMapping;\n"
            "import org.springframework.web.bind.annotation.PathVariable;\n"
            "import org.springframework.web.bind.annotation.RestController;\n\n"
            "@RestController\n"
            f"public final class {class_name} {{\n"
            "    private final Connection connection;\n\n"
            f"    public {class_name}(Connection connection) {{\n"
            "        this.connection = connection;\n"
            "    }\n\n"
            f"    @GetMapping({json.dumps(route_path, ensure_ascii=True)})\n"
            f"    public String {function_name}(@PathVariable String {parameter_name}) throws SQLException {{\n"
            "        Statement statement = connection.createStatement();\n"
            f"        ResultSet result = statement.executeQuery(\"SELECT {result_column} FROM {table_name} WHERE {lookup_column} = '\" + {parameter_name} + \"'\");\n"
            "        return result.toString();\n"
            "    }\n"
            "}\n"
        )
    elif state == "fixed":
        body = (
            f"package {package_name};\n\n"
            "import java.sql.Connection;\n"
            "import java.sql.PreparedStatement;\n"
            "import java.sql.ResultSet;\n"
            "import java.sql.SQLException;\n\n"
            "import org.springframework.web.bind.annotation.GetMapping;\n"
            "import org.springframework.web.bind.annotation.PathVariable;\n"
            "import org.springframework.web.bind.annotation.RestController;\n\n"
            "@RestController\n"
            f"public final class {class_name} {{\n"
            "    private final Connection connection;\n\n"
            f"    public {class_name}(Connection connection) {{\n"
            "        this.connection = connection;\n"
            "    }\n\n"
            f"    @GetMapping({json.dumps(route_path, ensure_ascii=True)})\n"
            f"    public String {function_name}(@PathVariable String {parameter_name}) throws SQLException {{\n"
            f"        PreparedStatement statement = connection.prepareStatement(\"SELECT {result_column} FROM {table_name} WHERE {lookup_column} = ?\");\n"
            f"        statement.setString(1, {parameter_name});\n"
            "        ResultSet result = statement.executeQuery();\n"
            "        return result.toString();\n"
            "    }\n"
            "}\n"
        )
    elif state == "negative":
        body = (
            f"package {package_name};\n\n"
            "import org.springframework.http.ResponseEntity;\n"
            "import org.springframework.web.bind.annotation.GetMapping;\n"
            "import org.springframework.web.bind.annotation.RestController;\n\n"
            "@RestController\n"
            f"public final class {class_name} {{\n"
            f"    @GetMapping({json.dumps(negative_route_path, ensure_ascii=True)})\n"
            f"    public ResponseEntity<String> {function_name}() {{\n"
            f"        return ResponseEntity.ok({json.dumps(static_message, ensure_ascii=True)});\n"
            "    }\n"
            "}\n"
        )
    else:
        raise ValueError("source_flow_slot_tree_state_invalid")
    return body.encode("ascii")


def _express_tree_files(slot_id: str, role: str, spec: Mapping[str, str], state: str) -> dict[str, bytes]:
    package = {
        "name": f"k-guard-generated-{slot_id}-{role}",
        "private": True,
        "type": "module",
        "version": "0.0.0",
    }
    return {
        "LICENSE": LICENSE_TEXT.encode("ascii"),
        "package.json": canonical_json_bytes(package),
        spec["route_path"]: _route_source(spec, state),
    }


def _go_chi_tree_files(slot_id: str, role: str, spec: Mapping[str, str], state: str) -> dict[str, bytes]:
    go_mod = (
        f"module example.com/k-guard-generated-{slot_id}-{role}\n\n"
        "go 1.22\n\n"
        "require github.com/go-chi/chi/v5 v5.1.0\n"
    )
    return {
        "LICENSE": LICENSE_TEXT.encode("ascii"),
        "go.mod": go_mod.encode("ascii"),
        spec["source_path"]: _go_chi_sql_builder_source(spec, state),
    }


def _go_pgx_tree_files(slot_id: str, role: str, spec: Mapping[str, str], state: str) -> dict[str, bytes]:
    go_mod = (
        f"module example.com/k-guard-generated-{slot_id}-{role}\n\n"
        "go 1.22\n\n"
        "require github.com/jackc/pgx/v5 v5.7.2\n"
    )
    return {
        "LICENSE": LICENSE_TEXT.encode("ascii"),
        "go.mod": go_mod.encode("ascii"),
        spec["source_path"]: _go_pgx_query_format_source(spec, state),
    }


def _typescript_prisma_tree_files(slot_id: str, role: str, spec: Mapping[str, str], state: str) -> dict[str, bytes]:
    package = {
        "dependencies": {"@prisma/client": "6.0.0"},
        "name": f"k-guard-generated-{slot_id}-{role}",
        "private": True,
        "type": "module",
        "version": "0.0.0",
    }
    return {
        "LICENSE": LICENSE_TEXT.encode("ascii"),
        "package.json": canonical_json_bytes(package),
        spec["source_path"]: _typescript_prisma_raw_query_source(spec, state),
    }


def _python_fastapi_tree_files(slot_id: str, role: str, spec: Mapping[str, str], state: str) -> dict[str, bytes]:
    pyproject = (
        "[project]\n"
        f'name = "k-guard-generated-{slot_id}-{role}"\n'
        'version = "0.0.0"\n'
        'requires-python = ">=3.11"\n'
        'dependencies = ["fastapi==0.115.0"]\n'
    )
    return {
        "LICENSE": LICENSE_TEXT.encode("ascii"),
        "pyproject.toml": pyproject.encode("ascii"),
        spec["source_path"]: _fastapi_parameterized_query_source(spec, state),
    }


def _java_spring_tree_files(slot_id: str, role: str, spec: Mapping[str, str], state: str) -> dict[str, bytes]:
    pom = (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.kguard.generated</groupId>\n"
        f"  <artifactId>{slot_id}-{role}</artifactId>\n"
        "  <version>0.0.0</version>\n"
        "  <properties><maven.compiler.release>17</maven.compiler.release></properties>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.springframework.boot</groupId>\n"
        "      <artifactId>spring-boot-starter-web</artifactId>\n"
        "      <version>3.3.0</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    return {
        "LICENSE": LICENSE_TEXT.encode("ascii"),
        "pom.xml": pom.encode("ascii"),
        spec["source_path"]: _java_spring_jdbc_concat_source(spec, state),
    }


RENDERER_TREE_BUILDERS = {
    "express-sql-query.v1": _express_tree_files,
    "go-chi-sql-builder.v1": _go_chi_tree_files,
    "go-pgx-query-format.v1": _go_pgx_tree_files,
    "typescript-prisma-raw-query.v1": _typescript_prisma_tree_files,
    "python-fastapi-parameterized-query.v1": _python_fastapi_tree_files,
    "java-spring-jdbc-concat.v1": _java_spring_tree_files,
}


def _tree_files(slot_id: str, candidate_rank: int, state: str) -> dict[str, bytes]:
    config = _slot_config(slot_id)
    spec = _candidate_spec(slot_id, candidate_rank)
    role = "primary" if candidate_rank == 0 else "reserve"
    try:
        builder = RENDERER_TREE_BUILDERS[config["renderer"]]
    except KeyError as exc:
        raise ValueError("source_flow_slot_renderer_invalid") from exc
    return builder(slot_id, role, spec, state)


def _tree_identity(files: Mapping[str, bytes]) -> str:
    projection = [{"path": path, "sha256": _sha256_bytes(content)} for path, content in sorted(files.items())]
    return _domain_hash(b"k_guard_l3_source_flow_slot_tree.v1\0", projection)


def _materialization_root_binding(slot_id: str, materialization_root: Path) -> str:
    return hashlib.sha256(
        b"k_guard_l3_source_flow_slot_root.v1\0"
        + slot_id.encode("ascii")
        + b"\0"
        + str(materialization_root.resolve(strict=True)).encode("utf-8")
    ).hexdigest()


def _express_template_projection(slot_id: str, rank: int, spec: Mapping[str, str]) -> dict[str, object]:
    return {
        "slot_id": slot_id,
        "template_id": spec["template_id"],
        "candidate_rank": rank,
        "route_path": spec["route_path"],
        "function_name": spec["function_name"],
        "input_name": spec["input_name"],
    }


def _go_chi_template_projection(slot_id: str, rank: int, spec: Mapping[str, str]) -> dict[str, object]:
    return {
        "slot_id": slot_id,
        "template_id": spec["template_id"],
        "candidate_rank": rank,
        "source_path": spec["source_path"],
        "package_name": spec["package_name"],
        "handler_name": spec["handler_name"],
        "route_path": spec["route_path"],
        "parameter_name": spec["parameter_name"],
        "table_name": spec["table_name"],
        "result_column": spec["result_column"],
        "static_message": spec["static_message"],
    }


def _go_pgx_template_projection(slot_id: str, rank: int, spec: Mapping[str, str]) -> dict[str, object]:
    return {
        "slot_id": slot_id,
        "template_id": spec["template_id"],
        "candidate_rank": rank,
        "source_path": spec["source_path"],
        "package_name": spec["package_name"],
        "function_name": spec["function_name"],
        "route_path": spec["route_path"],
        "negative_route_path": spec["negative_route_path"],
        "parameter_name": spec["parameter_name"],
        "lookup_column": spec["lookup_column"],
        "table_name": spec["table_name"],
        "result_column": spec["result_column"],
        "static_message": spec["static_message"],
    }


def _typescript_prisma_template_projection(slot_id: str, rank: int, spec: Mapping[str, str]) -> dict[str, object]:
    return {
        "slot_id": slot_id,
        "template_id": spec["template_id"],
        "candidate_rank": rank,
        "source_path": spec["source_path"],
        "function_name": spec["function_name"],
        "parameter_name": spec["parameter_name"],
        "table_name": spec["table_name"],
        "result_column": spec["result_column"],
        "static_message": spec["static_message"],
    }


def _fastapi_parameterized_query_template_projection(
    slot_id: str, rank: int, spec: Mapping[str, str]
) -> dict[str, object]:
    return {
        "slot_id": slot_id,
        "template_id": spec["template_id"],
        "candidate_rank": rank,
        "source_path": spec["source_path"],
        "function_name": spec["function_name"],
        "route_path": spec["route_path"],
        "negative_route_path": spec["negative_route_path"],
        "parameter_name": spec["parameter_name"],
        "lookup_column": spec["lookup_column"],
        "table_name": spec["table_name"],
        "result_column": spec["result_column"],
        "static_message": spec["static_message"],
    }


def _java_spring_jdbc_concat_template_projection(slot_id: str, rank: int, spec: Mapping[str, str]) -> dict[str, object]:
    return {
        "slot_id": slot_id,
        "template_id": spec["template_id"],
        "candidate_rank": rank,
        "source_path": spec["source_path"],
        "package_name": spec["package_name"],
        "class_name": spec["class_name"],
        "function_name": spec["function_name"],
        "route_path": spec["route_path"],
        "negative_route_path": spec["negative_route_path"],
        "parameter_name": spec["parameter_name"],
        "lookup_column": spec["lookup_column"],
        "table_name": spec["table_name"],
        "result_column": spec["result_column"],
        "static_message": spec["static_message"],
    }


RENDERER_TEMPLATE_PROJECTIONS = {
    "express-sql-query.v1": _express_template_projection,
    "go-chi-sql-builder.v1": _go_chi_template_projection,
    "go-pgx-query-format.v1": _go_pgx_template_projection,
    "typescript-prisma-raw-query.v1": _typescript_prisma_template_projection,
    "python-fastapi-parameterized-query.v1": _fastapi_parameterized_query_template_projection,
    "java-spring-jdbc-concat.v1": _java_spring_jdbc_concat_template_projection,
}

RENDERER_IDENTITY_FUNCTIONS = {
    "express-sql-query.v1": (_route_source, _express_tree_files, _express_template_projection),
    "go-chi-sql-builder.v1": (_go_chi_sql_builder_source, _go_chi_tree_files, _go_chi_template_projection),
    "go-pgx-query-format.v1": (
        _go_pgx_query_format_source,
        _go_pgx_tree_files,
        _go_pgx_template_projection,
    ),
    "typescript-prisma-raw-query.v1": (
        _typescript_prisma_raw_query_source,
        _typescript_prisma_tree_files,
        _typescript_prisma_template_projection,
    ),
    "python-fastapi-parameterized-query.v1": (
        _fastapi_parameterized_query_source,
        _python_fastapi_tree_files,
        _fastapi_parameterized_query_template_projection,
    ),
    "java-spring-jdbc-concat.v1": (
        _java_spring_jdbc_concat_source,
        _java_spring_tree_files,
        _java_spring_jdbc_concat_template_projection,
    ),
}


def _function_source_sha256(function: Any) -> str:
    try:
        source = inspect.getsource(function)
    except (OSError, TypeError) as exc:
        raise ValueError("source_flow_slot_renderer_identity_source_unavailable") from exc
    return _domain_hash(
        b"k_guard_l3_source_flow_slot_renderer_function.v1\0",
        {"qualname": function.__qualname__, "source": source},
    )


def materializer_identity(slot_id: str) -> dict[str, object]:
    config = _slot_config(slot_id)
    renderer = config["renderer"]
    try:
        renderer_contract_version = RENDERER_CONTRACT_VERSIONS[renderer]
        functions = RENDERER_IDENTITY_FUNCTIONS[renderer]
    except KeyError as exc:
        raise ValueError("source_flow_slot_renderer_invalid") from exc
    implementation = {
        "renderer": renderer,
        "renderer_contract_version": renderer_contract_version,
        "function_sha256": [
            {"name": function.__name__, "sha256": _function_source_sha256(function)} for function in functions
        ],
    }
    projection = {
        "schema": MATERIALIZER_IDENTITY_SCHEMA,
        "materialization_contract_version": MATERIALIZATION_CONTRACT_VERSION,
        "slot_id": slot_id,
        "slot_definition_sha256": _slot_definition_sha256(slot_id),
        "license_content_sha256": _sha256_bytes(LICENSE_TEXT.encode("ascii")),
        "renderer_implementation": implementation,
    }
    return {
        **projection,
        "sha256": _domain_hash(b"k_guard_l3_source_flow_slot_materializer_identity.v1\0", projection),
    }


def _template_projection(slot_id: str, rank: int, spec: Mapping[str, str]) -> dict[str, object]:
    try:
        projector = RENDERER_TEMPLATE_PROJECTIONS[_slot_config(slot_id)["renderer"]]
    except KeyError as exc:
        raise ValueError("source_flow_slot_renderer_invalid") from exc
    return projector(slot_id, rank, spec)


def _candidate_receipt(slot_id: str, candidate: Mapping[str, Any]) -> dict[str, Any]:
    rank = candidate["candidate_rank"]
    spec = _candidate_spec(slot_id, rank)
    trees = {state: _tree_files(slot_id, rank, state) for state in TRIPLET_STATES}
    identities = {state: _tree_identity(files) for state, files in trees.items()}
    if len(set(identities.values())) != len(TRIPLET_STATES):
        raise ValueError("source_flow_slot_tree_identity_not_differential")
    template_projection = _template_projection(slot_id, rank, spec)
    return {
        "slot_id": candidate["slot_id"],
        "scenario_id": candidate["scenario_id"],
        "oracle_id": candidate["oracle_id"],
        "candidate_rank": rank,
        "candidate_role": candidate["candidate_role"],
        "candidate_relative_root": candidate["candidate_relative_root"],
        "triplet_relative_paths": candidate["triplet_relative_paths"],
        "generator_profile": candidate["generator_profile"],
        "template_id": spec["template_id"],
        "template_identity_sha256": _domain_hash(b"k_guard_l3_source_flow_slot_template.v1\0", template_projection),
        "license_spdx": LICENSE_SPDX,
        "license_content_sha256": _sha256_bytes(LICENSE_TEXT.encode("ascii")),
        "tree_file_counts": {state: len(files) for state, files in trees.items()},
        "tree_sha256": {state: identities[state] for state in TRIPLET_STATES},
    }


def _expected_candidates(staging_receipt: Mapping[str, Any], slot_id: str) -> list[dict[str, Any]]:
    return [_candidate_receipt(slot_id, candidate) for candidate in _slot_candidates(staging_receipt, slot_id)]


def _expected_counts(candidates: list[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "slot_count": 1,
        "candidate_count": len(candidates),
        "primary_candidate_count": sum(candidate["candidate_role"] == "primary" for candidate in candidates),
        "reserve_candidate_count": sum(candidate["candidate_role"] == "reserve" for candidate in candidates),
        "source_triplet_count": len(candidates) * len(TRIPLET_STATES),
        "source_file_count": sum(sum(candidate["tree_file_counts"].values()) for candidate in candidates),
    }


def _expected_files(staging_receipt: Mapping[str, Any], slot_id: str) -> dict[str, bytes]:
    expected: dict[str, bytes] = {}
    for candidate in _slot_candidates(staging_receipt, slot_id):
        for state in TRIPLET_STATES:
            for relative_path, content in _tree_files(slot_id, candidate["candidate_rank"], state).items():
                source_path = f"{candidate['triplet_relative_paths'][state]}/{relative_path}"
                if source_path in expected:
                    raise ValueError("source_flow_slot_source_path_duplicate")
                expected[source_path] = content
    return expected


def _expected_directories(expected_files: Mapping[str, bytes]) -> set[str]:
    directories: set[str] = set()
    for raw_path in expected_files:
        current = PurePosixPath(raw_path).parent
        while str(current) != ".":
            directories.add(current.as_posix())
            current = current.parent
    return directories


def _validate_materialization_tree(materialization_root: Path, staging_receipt: Mapping[str, Any], slot_id: str) -> None:
    _require_external_path(materialization_root, "source_flow_slot_materialization_root_must_be_external")
    if not materialization_root.is_dir() or materialization_root.is_symlink():
        raise ValueError("source_flow_slot_materialization_root_path_invalid")
    expected_files = _expected_files(staging_receipt, slot_id)
    actual_files: dict[str, Path] = {}
    actual_directories: set[str] = set()
    for path in materialization_root.rglob("*"):
        if path.is_symlink():
            raise ValueError("source_flow_slot_materialization_symlink_forbidden")
        relative = path.relative_to(materialization_root).as_posix()
        if path.is_dir():
            actual_directories.add(relative)
        elif path.is_file():
            actual_files[relative] = path
        else:
            raise ValueError("source_flow_slot_materialization_entry_type_invalid")
    if set(actual_files) != set(expected_files):
        raise ValueError("source_flow_slot_materialization_file_set_invalid")
    if actual_directories != _expected_directories(expected_files):
        raise ValueError("source_flow_slot_materialization_directory_set_invalid")
    for relative_path, expected_content in expected_files.items():
        if actual_files[relative_path].read_bytes() != expected_content:
            raise ValueError("source_flow_slot_materialization_source_content_invalid")


def _build_receipt(
    *,
    slot_id: str,
    staging_receipt: Mapping[str, Any],
    staging_receipt_artifact_sha256: str,
    stager_sha256: str,
    materialization_root: Path,
) -> dict[str, Any]:
    candidates = _expected_candidates(staging_receipt, slot_id)
    _validate_materialization_tree(materialization_root, staging_receipt, slot_id)
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "blueprint": dict(staging_receipt["blueprint"]),
        "staging_binding": {
            "staging_receipt_artifact_sha256": staging_receipt_artifact_sha256,
            "stage_root_binding_sha256": staging_receipt["stage_root_binding_sha256"],
            "stage_tree_identity_sha256": staging_receipt["stage_tree_identity_sha256"],
            "stager_sha256": stager_sha256,
        },
        "materialization_root_binding_sha256": _materialization_root_binding(slot_id, materialization_root),
        "slot_id": slot_id,
        "slot_definition_sha256": _slot_definition_sha256(slot_id),
        "candidates": candidates,
        "counts": _expected_counts(candidates),
        "claim_boundary": CLAIM_BOUNDARY,
        "raw_source_returned": False,
        "materializer_identity": materializer_identity(slot_id),
    }


def validate_materialization_receipt(
    value: object,
    *,
    slot_id: str,
    staging_receipt: Mapping[str, Any],
    staging_receipt_artifact_sha256: str,
    stager_sha256: str,
    materialization_root: Path,
) -> dict[str, Any]:
    _slot_config(slot_id)
    if not isinstance(value, Mapping):
        raise ValueError("source_flow_slot_materialization_receipt_not_object")
    common_keys = {
        "schema", "version", "blueprint", "staging_binding", "materialization_root_binding_sha256",
        "slot_id", "slot_definition_sha256", "candidates", "counts", "claim_boundary",
        "raw_source_returned",
    }
    receipt_version = (value.get("schema"), value.get("version"))
    if receipt_version == (SCHEMA, VERSION):
        expected_keys = common_keys | {"materializer_identity"}
        provenance = "v2"
    elif receipt_version == (SCHEMA_V1, VERSION_V1):
        expected_keys = common_keys | {"materializer_sha256"}
        provenance = "v1"
    else:
        raise ValueError("source_flow_slot_materialization_receipt_schema_or_version_invalid")
    if set(value) != expected_keys:
        raise ValueError("source_flow_slot_materialization_receipt_keys_invalid")
    if value["blueprint"] != staging_receipt["blueprint"]:
        raise ValueError("source_flow_slot_materialization_blueprint_binding_invalid")
    expected_staging_binding = {
        "staging_receipt_artifact_sha256": staging_receipt_artifact_sha256,
        "stage_root_binding_sha256": staging_receipt["stage_root_binding_sha256"],
        "stage_tree_identity_sha256": staging_receipt["stage_tree_identity_sha256"],
        "stager_sha256": stager_sha256,
    }
    if value["staging_binding"] != expected_staging_binding:
        raise ValueError("source_flow_slot_materialization_staging_binding_invalid")
    if value["materialization_root_binding_sha256"] != _materialization_root_binding(slot_id, materialization_root):
        raise ValueError("source_flow_slot_materialization_root_binding_mismatch")
    if value["slot_id"] != slot_id:
        raise ValueError("source_flow_slot_materialization_slot_invalid")
    if value["slot_definition_sha256"] != _slot_definition_sha256(slot_id):
        raise ValueError("source_flow_slot_definition_binding_invalid")
    candidates = _expected_candidates(staging_receipt, slot_id)
    if value["candidates"] != candidates:
        raise ValueError("source_flow_slot_materialization_candidates_invalid")
    if value["counts"] != _expected_counts(candidates):
        raise ValueError("source_flow_slot_materialization_counts_invalid")
    if value["claim_boundary"] != CLAIM_BOUNDARY or value["raw_source_returned"] is not False:
        raise ValueError("source_flow_slot_materialization_claim_boundary_invalid")
    if provenance == "v2":
        if value["materializer_identity"] != materializer_identity(slot_id):
            raise ValueError("source_flow_slot_materializer_identity_mismatch")
    elif value["materializer_sha256"] not in LEGACY_WHOLE_MODULE_SHA256_BY_SLOT.get(slot_id, frozenset()):
        raise ValueError("source_flow_slot_materializer_sha256_mismatch")
    _validate_materialization_tree(materialization_root, staging_receipt, slot_id)
    return dict(value)


def _write_receipt(output: Path, receipt: Mapping[str, Any]) -> None:
    _require_external_path(output, "source_flow_slot_materialization_receipt_output_must_be_external")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_source_flow_slot_materialization_receipt")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(receipt)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_source_flow_slot_materialization_receipt") from exc


def materialize_slot(
    *,
    slot_id: str,
    blueprint_path: Path,
    staging_receipt_path: Path,
    staging_root: Path,
    materialization_root: Path,
    output: Path,
) -> dict[str, Any]:
    _slot_config(slot_id)
    for path, error in (
        (materialization_root, "source_flow_slot_materialization_root_must_be_external"),
        (output, "source_flow_slot_materialization_receipt_output_must_be_external"),
    ):
        _require_external_path(path, error)
    if materialization_root.exists() or materialization_root.is_symlink():
        raise ValueError("refusing_to_overwrite_source_flow_slot_materialization_root")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_source_flow_slot_materialization_receipt")
    if any(_paths_overlap(materialization_root, other) for other in (blueprint_path, staging_receipt_path, staging_root, output)):
        raise ValueError("source_flow_slot_materialization_paths_must_not_overlap_inputs_or_receipt")
    staging_receipt, staging_receipt_sha256, stager_sha256 = _load_staging_inputs(
        blueprint_path, staging_receipt_path, staging_root
    )
    materialization_root.mkdir(parents=True, exist_ok=False)
    for relative_path, content in _expected_files(staging_receipt, slot_id).items():
        destination = materialization_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    receipt = _build_receipt(
        slot_id=slot_id,
        staging_receipt=staging_receipt,
        staging_receipt_artifact_sha256=staging_receipt_sha256,
        stager_sha256=stager_sha256,
        materialization_root=materialization_root,
    )
    _write_receipt(output, receipt)
    return receipt


def load_materialization_receipt(
    *,
    slot_id: str,
    blueprint_path: Path,
    staging_receipt_path: Path,
    staging_root: Path,
    materialization_root: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    _slot_config(slot_id)
    _require_external_path(receipt_path, "source_flow_slot_materialization_receipt_must_be_external")
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise ValueError("source_flow_slot_materialization_receipt_path_invalid")
    raw = receipt_path.read_bytes()
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("source_flow_slot_materialization_receipt_json_invalid") from exc
    if canonical_json_bytes(value) != raw:
        raise ValueError("source_flow_slot_materialization_receipt_not_canonical")
    staging_receipt, staging_receipt_sha256, stager_sha256 = _load_staging_inputs(
        blueprint_path, staging_receipt_path, staging_root
    )
    return validate_materialization_receipt(
        value,
        slot_id=slot_id,
        staging_receipt=staging_receipt,
        staging_receipt_artifact_sha256=staging_receipt_sha256,
        stager_sha256=stager_sha256,
        materialization_root=materialization_root,
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize one preregistered source-flow slot source triplet pair.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("materialize", "validate"):
        command = subparsers.add_parser(name)
        command.add_argument("--slot-id", required=True)
        command.add_argument("--blueprint", type=Path, required=True)
        command.add_argument("--staging-receipt", type=Path, required=True)
        command.add_argument("--staging-root", type=Path, required=True)
        command.add_argument("--materialization-root", type=Path, required=True)
        command.add_argument("--output" if name == "materialize" else "--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "materialize":
            receipt = materialize_slot(
                slot_id=args.slot_id,
                blueprint_path=args.blueprint,
                staging_receipt_path=args.staging_receipt,
                staging_root=args.staging_root,
                materialization_root=args.materialization_root,
                output=args.output,
            )
        else:
            receipt = load_materialization_receipt(
                slot_id=args.slot_id,
                blueprint_path=args.blueprint,
                staging_receipt_path=args.staging_receipt,
                staging_root=args.staging_root,
                materialization_root=args.materialization_root,
                receipt_path=args.input,
            )
    except (OSError, ValueError) as exc:
        print(f"materialize_l3_source_flow_slot: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"materialized_candidate_count": receipt["counts"]["candidate_count"], "raw_source_returned": False, "source_triplets_materialized": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
