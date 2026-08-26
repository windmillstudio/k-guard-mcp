from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "materialize_l2_sources.py"
SPEC = importlib.util.spec_from_file_location("materialize_l2_sources_test", SCRIPT)
assert SPEC and SPEC.loader
l2 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(l2)
source_materialization = l2._load_source_materialization()


def test_official_six_app_identity_preregistration_is_exact_and_immutable() -> None:
    expected = {
        "crapi": (
            "owasp/crapi",
            "73d309cc8f28bbdeed31dbb35f05dba8354de3c9",
            "86d22e42ca8f8e3c903f30146ad0df51483b8df0",
            "f76c89d35f9b7d34c3b12c6b2f64177e0845957f85fab52613bbc18354925d52",
            "d86a9985f9eda5e391112a26a092f7a5273bde393c386ae8968f91399df7429b",
            "LICENSE.md",
            "Apache-2.0",
            "c98881e3c37ee7331ff667bc0ae59415e5405ea18974c50fa44cd0308623415c",
            11311,
        ),
        "juice-shop": (
            "juice-shop/juice-shop",
            "33518f5a0911e25d9df747b1e70fb7af279a755c",
            "d503a1d2f1a8864ba596fbf3f6d23dfa02cf45a6",
            "9a109ac9217946774a0c5d356d2a9836c06153d4ae1fe21de92aa71556525fae",
            "4ed955ad49e650a12139a21e8fc0491a102fd346e4920ca771668e3cf0f9a93a",
            "LICENSE",
            "MIT",
            "fa4ca6d61009e537c953f1c0b8455dd66d69f810888546c48db8ea05f0713093",
            1101,
        ),
        "nodegoat": (
            "owasp/nodegoat",
            "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
            "839d7b6856ec6da992d649b2423d5f9fcefdcf1f",
            "352404981579791fafc18f70649c772a03f304b8895c4f239fbd9863ef5f8a52",
            "d3ad5d453bb7d35580f3bf21dfcbab1bbf53555b7144f94da917cd6513ee21ab",
            "LICENSE",
            "Apache-2.0",
            "73ba74dfaa520b49a401b5d21459a8523a146f3b7518a833eea5efa85130bf68",
            10273,
        ),
        "pygoat": (
            "adeyosemanputra/pygoat",
            "19d17cc8874861142b330636d068bbde54e86b85",
            "1ee82a01f5ac80df289327eca929c9f5aff2a9c4",
            "156486b1531432930bf9df68f2886a20531c28a7aeffe95c9f095286eee3821c",
            "0bf2824174f6e979893bda964f87e394c3689db69a3825cab646880156f2fa5c",
            "LICENSE.md",
            "MIT",
            "f3e0249f489c8823e83c5f6e4a65795e624ef9024381722f21592134dcab611f",
            1063,
        ),
        "webgoat": (
            "webgoat/webgoat",
            "5142935bf7c279882c3b0fc0ecec42c447de6fd5",
            "6c45e60db0995416a5bbe5977657a78d5084dcf7",
            "0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c",
            "7755ce29a5450b9803f46effb6f42fe7624e39b317c99546eb74624a3380b83b",
            "LICENSE.txt",
            "GPL-2.0-or-later",
            "2fea812568866fdb6ff99671ad70465bfc25ab77f86129795d08d961c30d2ca1",
            1092,
        ),
        "wrongsecrets": (
            "owasp/wrongsecrets",
            "25bdda3c380c7b16bdd2a528c9fff3700fa2b801",
            "4946781597334bc73adb26d97d84f2677264f9d1",
            "9b85876c204c995d056206a292ba45e48731ce2a71124fc5e43f4cdea6eeff80",
            "58509e4ad992c66e1b230a66d9f7e18c6c080aea07fb110e07b08d4295455485",
            "LICENSE",
            "AGPL-3.0-only",
            "a3c8862ad142ce7c8a915663dc397c2fb56bbc61a1d1ba9dfebb55b0931c37d6",
            34479,
        ),
    }
    actual = {
        app_id: (
            identity["repository_id"],
            identity["commit"],
            identity["commit_tree"],
            identity["source_tree_sha256"],
            identity["receipt_sha256"],
            identity["license"]["path"],
            identity["license"]["spdx"],
            identity["license"]["sha256"],
            identity["license"]["byte_count"],
        )
        for app_id, identity in l2.EXPECTED_IDENTITIES.items()
    }

    assert actual == expected
    with pytest.raises(TypeError):
        l2.EXPECTED_IDENTITIES["crapi"] = {}  # type: ignore[index]


def test_authoritative_wrongsecrets_seed_payload_matches_locked_identity() -> None:
    raw = (
        b'{"app_id":"wrongsecrets","commit":"25bdda3c380c7b16bdd2a528c9fff3700fa2b801",'
        b'"commit_tree":"4946781597334bc73adb26d97d84f2677264f9d1",'
        b'"license":{"byte_count":34479,"path":"LICENSE",'
        b'"sha256":"a3c8862ad142ce7c8a915663dc397c2fb56bbc61a1d1ba9dfebb55b0931c37d6",'
        b'"spdx":"AGPL-3.0-only"},'
        b'"receipt_sha256":"58509e4ad992c66e1b230a66d9f7e18c6c080aea07fb110e07b08d4295455485",'
        b'"repository_id":"owasp/wrongsecrets",'
        b'"source_tree_sha256":"9b85876c204c995d056206a292ba45e48731ce2a71124fc5e43f4cdea6eeff80"}'
    )
    authoritative = json.loads(raw.decode("ascii"))
    app_id = authoritative.pop("app_id")
    locked = dict(l2.EXPECTED_IDENTITIES[app_id])
    locked["license"] = dict(locked["license"])
    semantic_sha256 = locked.pop("receipt_semantic_sha256")

    assert l2.sha256_bytes(raw) == (
        "c25cd0d3d13b6edad9b79ed66895ece9c8d75ce28fd354e1dffa0f4ad91de00a"
    )
    assert semantic_sha256 == "06f9b90faa43039cd5093b577fb63f98d855134e852ab35bc40c331d423c2bba"
    assert authoritative == locked


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _write_canonical(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(l2.canonical_json_bytes(payload))


def _rewrite_seed(seed_path: Path, mutate) -> dict:
    payload = json.loads(seed_path.read_text(encoding="utf-8"))
    mutate(payload)
    _write_canonical(seed_path, payload)
    return payload


def _rewrite_receipt(seed_path: Path, app_index: int, mutate, *, rebind: bool) -> None:
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    app = seed["apps"][app_index]
    receipt_path = seed_path.parent / app["receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    mutate(receipt)
    raw = l2.canonical_json_bytes(receipt)
    receipt_path.write_bytes(raw)
    if rebind:
        app["receipt_sha256"] = l2.sha256_bytes(raw)
        _write_canonical(seed_path, seed)


@pytest.fixture(scope="module")
def l2_template(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict]:
    tmp_path = tmp_path_factory.mktemp("l2-template")
    apps: list[dict] = []
    identities: dict[str, dict] = {}
    for index, app_id in enumerate(sorted(l2.EXPECTED_APPS)):
        root = tmp_path / "checkouts" / app_id
        root.mkdir(parents=True)
        _git(root, "init", "--initial-branch=main")
        _git(root, "config", "user.email", "l2@example.invalid")
        _git(root, "config", "user.name", "L2 Fixture")
        _git(root, "config", "core.autocrlf", "false")
        repository_id = f"k-guard-fixtures/{app_id}"
        _git(root, "remote", "add", "origin", f"https://github.com/{repository_id}.git")
        license_raw = f"MIT License for {app_id}\n".encode("utf-8")
        (root / "LICENSE").write_bytes(license_raw)
        (root / "app.txt").write_text(f"fixture={app_id};index={index}\n", encoding="utf-8")
        _git(root, "add", "--all")
        _git(root, "commit", "-m", f"bind {app_id}")
        commit = _git(root, "rev-parse", "HEAD")
        tree = _git(root, "rev-parse", "HEAD^{tree}")
        receipt = source_materialization.build_git_materialization_receipt(
            root,
            expected_repository_id=repository_id,
            expected_commit=commit,
            expected_tree=tree,
        )
        receipt_path = tmp_path / "receipts" / f"{app_id}.json"
        receipt_raw = l2.canonical_json_bytes(receipt)
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_bytes(receipt_raw)
        source_tree = receipt["source_tree_sha256"]
        license_binding = {
            "path": "LICENSE",
            "spdx": "MIT",
            "sha256": l2.sha256_bytes(license_raw),
            "byte_count": len(license_raw),
        }
        identity = {
            "repository_id": repository_id,
            "commit": commit,
            "commit_tree": tree,
            "source_tree_sha256": source_tree,
            "receipt_sha256": l2.sha256_bytes(receipt_raw),
            "receipt_semantic_sha256": l2._source_receipt_semantic_sha256(receipt),
            "license": license_binding,
        }
        identities[app_id] = copy.deepcopy(identity)
        apps.append(
            {
                "app_id": app_id,
                **identity,
                "lineage_id": l2.compute_lineage_id(
                    app_id, repository_id, commit, tree, source_tree
                ),
                "checkout_root": f"checkouts/{app_id}",
                "receipt_path": f"receipts/{app_id}.json",
                "receipt_equivalence": "exact_raw_receipt",
                "isolation": {field: True for field in l2.ISOLATION_FIELDS},
                "machine_oracles": [
                    {
                        "scenario_id": f"{app_id}-declared-001",
                        "status": "present",
                        "reason": "machine_oracle_declared_not_executed",
                    }
                ],
            }
        )
    seed_path = tmp_path / "seed.json"
    _write_canonical(seed_path, {"schema": l2.SEED_SCHEMA, "apps": apps})
    return seed_path, identities


@pytest.fixture()
def l2_seed(
    tmp_path: Path,
    l2_template: tuple[Path, dict],
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    template_path, identities = l2_template
    shutil.copytree(template_path.parent, tmp_path, dirs_exist_ok=True)
    monkeypatch.setattr(l2, "EXPECTED_IDENTITIES", copy.deepcopy(identities))
    return tmp_path / "seed.json"


def test_materialization_is_deterministic_and_never_claims_oracle_pass(
    l2_seed: Path,
) -> None:
    first = l2.materialize_l2_sources(l2_seed)
    second = l2.materialize_l2_sources(l2_seed)

    assert first == second
    assert l2.canonical_json_bytes(first) == l2.canonical_json_bytes(second)
    assert [row["app_id"] for row in first["apps"]] == sorted(l2.EXPECTED_APPS)
    assert first["source_license_admission"] == "PASS"
    assert first["isolation_contract_declared"] == "PASS"
    assert first["runtime_isolation_gate"] == "HOLD"
    assert first["runtime_isolation_gate_reason"] == (
        "docker_runtime_receipts_not_observed"
    )
    assert first["tool_provenance"]["materializer_sha256"] == l2.sha256_bytes(
        SCRIPT.read_bytes()
    )
    assert first["tool_provenance"]["verifier_sha256"] == l2.sha256_bytes(
        (ROOT / "scripts" / "holdout_source_materialization.py").read_bytes()
    )
    assert first["machine_oracle_gate"] == "HOLD"
    assert first["phase_2_status"] == "HOLD"
    assert first["release_gate_passed"] is False
    assert first["scanner_output_observed"] is False
    assert all(row["scanner_output_observed"] is False for row in first["apps"])
    assert all(row["oracle_gate_status"] == "HOLD" for row in first["apps"])
    assert all(
        row["isolation_contract"]["declared_status"] == "PASS"
        and row["isolation_contract"]["runtime_evidence_observed"] is False
        and row["isolation_contract"]["runtime_gate"] == "HOLD"
        for row in first["apps"]
    )


def test_receipt_byte_tamper_is_rejected(l2_seed: Path) -> None:
    _rewrite_receipt(
        l2_seed,
        0,
        lambda receipt: receipt.__setitem__("raw_returned", True),
        rebind=False,
    )

    with pytest.raises(ValueError, match="byte hash"):
        l2.materialize_l2_sources(l2_seed)


def test_rebound_receipt_is_rejected_by_immutable_identity(l2_seed: Path) -> None:
    _rewrite_receipt(
        l2_seed,
        0,
        lambda receipt: receipt.__setitem__("total_bytes", receipt["total_bytes"] + 1),
        rebind=True,
    )

    with pytest.raises(ValueError, match="clean checkout verification"):
        l2.materialize_l2_sources(l2_seed)


def test_semantic_receipt_binding_rejects_any_non_porcelain_change(
    l2_seed: Path,
) -> None:
    _rewrite_seed(
        l2_seed,
        lambda seed: seed["apps"][0].__setitem__("receipt_semantic_sha256", "f" * 64),
    )

    with pytest.raises(ValueError, match="semantic hash differs from seed binding"):
        l2.materialize_l2_sources(l2_seed)


def test_receipt_equivalence_is_bound_to_observed_receipt(l2_seed: Path) -> None:
    _rewrite_seed(
        l2_seed,
        lambda seed: seed["apps"][0].__setitem__(
            "receipt_equivalence", "informational_porcelain_variance"
        ),
    )

    with pytest.raises(ValueError, match="equivalence differs from seed binding"):
        l2.materialize_l2_sources(l2_seed)


def test_duplicate_app_is_rejected(l2_seed: Path) -> None:
    def duplicate(seed: dict) -> None:
        seed["apps"][-1] = copy.deepcopy(seed["apps"][0])

    _rewrite_seed(l2_seed, duplicate)

    with pytest.raises(ValueError, match="app set is missing or duplicated"):
        l2.materialize_l2_sources(l2_seed)


def test_wrong_repository_is_rejected_before_receipt_verification(l2_seed: Path) -> None:
    def wrong_repository(seed: dict) -> None:
        target = seed["apps"][0]
        target["repository_id"] = "attacker/arbitrary-repository"
        target["lineage_id"] = l2.compute_lineage_id(
            target["app_id"],
            target["repository_id"],
            target["commit"],
            target["commit_tree"],
            target["source_tree_sha256"],
        )

    _rewrite_seed(l2_seed, wrong_repository)

    with pytest.raises(ValueError, match="immutable preregistration"):
        l2.materialize_l2_sources(l2_seed)


def test_swapped_app_identity_is_rejected_even_when_receipt_is_consistent(
    l2_seed: Path,
) -> None:
    def swap_identity(seed: dict) -> None:
        source = seed["apps"][0]
        target = seed["apps"][1]
        for field in (
            "repository_id",
            "commit",
            "commit_tree",
            "source_tree_sha256",
            "checkout_root",
            "receipt_path",
            "receipt_sha256",
            "license",
        ):
            target[field] = copy.deepcopy(source[field])
        target["lineage_id"] = l2.compute_lineage_id(
            target["app_id"],
            target["repository_id"],
            target["commit"],
            target["commit_tree"],
            target["source_tree_sha256"],
        )

    _rewrite_seed(l2_seed, swap_identity)

    with pytest.raises(ValueError, match="immutable preregistration"):
        l2.materialize_l2_sources(l2_seed)


def test_missing_app_is_rejected(l2_seed: Path) -> None:
    _rewrite_seed(l2_seed, lambda seed: seed["apps"].pop())

    with pytest.raises(ValueError, match="exactly six apps"):
        l2.materialize_l2_sources(l2_seed)


def test_license_binding_and_root_path_are_required(l2_seed: Path) -> None:
    _rewrite_seed(
        l2_seed,
        lambda seed: seed["apps"][0]["license"].__setitem__("path", "docs/LICENSE"),
    )

    with pytest.raises(ValueError, match="immutable preregistration"):
        l2.materialize_l2_sources(l2_seed)


def test_license_content_tamper_is_rejected_by_clean_source_admission(
    l2_seed: Path,
) -> None:
    seed = json.loads(l2_seed.read_text(encoding="utf-8"))
    root = l2_seed.parent / seed["apps"][0]["checkout_root"]
    (root / "LICENSE").write_text("changed license\n", encoding="utf-8")

    with pytest.raises(ValueError, match="materialized source"):
        l2.materialize_l2_sources(l2_seed)


def test_partial_clone_configuration_is_rejected(l2_seed: Path) -> None:
    seed = json.loads(l2_seed.read_text(encoding="utf-8"))
    root = l2_seed.parent / seed["apps"][0]["checkout_root"]
    _git(root, "config", "remote.origin.promisor", "true")

    with pytest.raises(ValueError, match="config key is not allowed"):
        l2.materialize_l2_sources(l2_seed)


def test_promisor_pack_marker_is_rejected(l2_seed: Path) -> None:
    seed = json.loads(l2_seed.read_text(encoding="utf-8"))
    root = l2_seed.parent / seed["apps"][0]["checkout_root"]
    marker = root / ".git" / "objects" / "pack" / "fixture.promisor"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(b"")

    with pytest.raises(ValueError, match="promisor object markers"):
        l2.materialize_l2_sources(l2_seed)


@pytest.mark.parametrize("field", l2.ISOLATION_FIELDS)
def test_every_isolation_declaration_is_mandatory(l2_seed: Path, field: str) -> None:
    _rewrite_seed(
        l2_seed,
        lambda seed: seed["apps"][0]["isolation"].__setitem__(field, False),
    )

    with pytest.raises(ValueError, match="exactly true"):
        l2.materialize_l2_sources(l2_seed)


def test_empty_and_uncertain_oracles_are_explicit_hold(l2_seed: Path) -> None:
    def change_oracles(seed: dict) -> None:
        seed["apps"][0]["machine_oracles"] = []
        seed["apps"][1]["machine_oracles"] = [
            {
                "scenario_id": "uncertain-001",
                "status": "uncertain",
                "reason": "upstream challenge lacks deterministic assertion",
            }
        ]

    _rewrite_seed(l2_seed, change_oracles)
    result = l2.materialize_l2_sources(l2_seed)
    by_id = {row["app_id"]: row for row in result["apps"]}
    first_id = json.loads(l2_seed.read_text(encoding="utf-8"))["apps"][0]["app_id"]
    second_id = json.loads(l2_seed.read_text(encoding="utf-8"))["apps"][1]["app_id"]

    assert by_id[first_id]["oracle_missing"] is True
    assert by_id[second_id]["oracle_uncertain"] is True
    assert result["machine_oracle_gate"] == "HOLD"
    assert result["release_gate_passed"] is False


def test_malformed_noncanonical_seed_fails_closed(l2_seed: Path) -> None:
    payload = json.loads(l2_seed.read_text(encoding="utf-8"))
    l2_seed.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="canonical JSON"):
        l2.materialize_l2_sources(l2_seed)


def test_output_refuses_overwrite(l2_seed: Path) -> None:
    output = l2_seed.parent / "result.json"
    output.write_text("existing\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        l2.write_new_output(output, l2.materialize_l2_sources(l2_seed))
    assert output.read_text(encoding="utf-8") == "existing\n"


def test_output_creation_race_does_not_overwrite(
    l2_seed: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = l2_seed.parent / "raced-result.json"
    original_link = l2.os.link

    def race_link(source: Path, destination: Path) -> None:
        destination.write_text("racing writer\n", encoding="utf-8")
        original_link(source, destination)

    monkeypatch.setattr(l2.os, "link", race_link)

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        l2.write_new_output(output, l2.materialize_l2_sources(l2_seed))
    assert output.read_text(encoding="utf-8") == "racing writer\n"
