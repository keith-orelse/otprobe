"""Phase 1 checks: design artifacts are valid and consistent with each other."""

from __future__ import annotations

import ast
import inspect
import json
import re
from pathlib import Path

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
RULES_DIR = ROOT / "rules"
DOCS_DIR = ROOT / "docs"
APP_DIR = ROOT / "backend" / "app"

POLICY_FILES = sorted(p for p in RULES_DIR.glob("*.yaml") if "policy" in yaml.safe_load(p.read_text()))
FORBIDDEN_IMPORTS = {"socket", "subprocess", "scapy", "pysnmp", "winrm", "pypsrp", "paramiko", "asyncssh",
                     "icmplib", "requests", "httpx", "urllib", "aiohttp", "paho", "aiomqtt", "ssl"}


@pytest.fixture(scope="module")
def rule_schema() -> dict:
    return json.loads((RULES_DIR / "schema.json").read_text())


@pytest.fixture(scope="module")
def openapi() -> dict:
    return yaml.safe_load((DOCS_DIR / "api" / "openapi.yaml").read_text())


@pytest.mark.parametrize("path", POLICY_FILES, ids=lambda p: p.name)
def test_policy_files_match_schema(path: Path, rule_schema: dict) -> None:
    jsonschema.validate(yaml.safe_load(path.read_text()), rule_schema)


def test_rule_ids_unique_across_policies() -> None:
    ids = [r["id"] for p in POLICY_FILES for r in yaml.safe_load(p.read_text())["rules"]]
    assert len(ids) == len(set(ids)), sorted(i for i in ids if ids.count(i) > 1)


@pytest.mark.parametrize("path", POLICY_FILES, ids=lambda p: p.name)
def test_condition_parameters_are_defined(path: Path) -> None:
    doc = yaml.safe_load(path.read_text())
    params = set(doc.get("parameters") or {})
    for rule in doc["rules"]:
        for ref in re.findall(r"\$([a-z_][a-z0-9_]*)", rule["condition"]):
            assert ref in params, f"{rule['id']} references undefined parameter ${ref}"


def test_openapi_refs_resolve(openapi: dict) -> None:
    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "$ref":
                    yield v
                else:
                    yield from walk(v)
        elif isinstance(node, list):
            for v in node:
                yield from walk(v)

    for ref in walk(openapi):
        target = openapi
        for part in ref.lstrip("#/").split("/"):
            assert part in target, f"unresolved $ref {ref}"
            target = target[part]


def test_openapi_is_valid_spec(openapi: dict) -> None:
    validator = pytest.importorskip("openapi_spec_validator")
    validator.validate(openapi)


def test_every_demo_control_is_in_failure_matrix(openapi: dict) -> None:
    matrix = (DOCS_DIR / "FAILURE_MATRIX.md").read_text()
    config_controls = {"power", "winrm", "firewall", "antivirus", "unauthorized_software", "remove_patch"}
    controls = set(openapi["components"]["schemas"]["DemoControl"]["properties"]["control"]["enum"])
    missing = [c for c in controls - config_controls if f"`{c}`" not in matrix]
    assert not missing, f"controls without a failure-matrix row: {missing}"


def test_adapter_interfaces_are_abstract() -> None:
    from app.adapters import base

    for name in ("IcmpAdapter", "ArpAdapter", "SnmpAdapter", "WinRmAdapter", "WmiAdapter", "MqttAdapter",
                 "SshAdapter", "PackageTransfer", "CredentialVault"):
        cls = getattr(base, name)
        assert inspect.isabstract(cls), f"{name} must be abstract"


SIM_DIR = Path(__file__).resolve().parents[1] / "sim"


def test_simulated_code_has_no_network_imports() -> None:
    """The in-process simulator never touches a network. (tests/sim/agent and tests/sim/telemetry are the separate
    agent-runtime and telemetry-simulator processes: they talk HTTP to the API on loopback by design.)"""
    for path in SIM_DIR.rglob("*.py"):
        if path.relative_to(SIM_DIR).parts[0] in ("agent", "telemetry"):
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for n in names:
                assert n.split(".")[0] not in FORBIDDEN_IMPORTS, f"{path}: forbidden import {n}"


def test_product_never_imports_the_test_suite() -> None:
    """The simulator lives in tests/sim (phase L6): nothing under app/ may import it, or anything else from tests."""
    for path in APP_DIR.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
            for n in names:
                assert n.split(".")[0] != "tests", f"{path}: imports {n}"
    assert not (APP_DIR / "sim").exists() and not (APP_DIR / "adapters" / "simulated").exists()
