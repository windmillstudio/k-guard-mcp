from __future__ import annotations

import copy
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import k_guard_mcp.h100_selector as selector
from k_guard_mcp.h100_selector import (
    GENERATOR_QUOTAS,
    H100ContractError,
    beacon_pulse_sha256,
    candidate_pool_sha256,
    select_h100,
)


PLANES = ("site", "api", "data", "operations")
FAMILIES = ("template", "codex", "claude", "grok")


def _scenarios(prefix: str) -> list[dict[str, str]]:
    rows = []
    for index in range(4):
        rows.append(
            {
                "scenario_id": f"{prefix}-positive-{index}",
                "root_cause_id": f"{prefix}-positive-root-{index}",
                "kind": "positive",
                "severity": "critical" if index == 0 else "high",
            }
        )
        rows.append(
            {
                "scenario_id": f"{prefix}-negative-{index}",
                "root_cause_id": f"{prefix}-negative-root-{index}",
                "kind": "negative",
                "severity": "none",
            }
        )
    return rows


def _candidate_pool() -> list[dict]:
    rows = []
    for plane in PLANES:
        for index in range(7):
            lineage = f"public-{plane}-{index:02d}"
            rows.append(
                {
                    "lineage_id": lineage,
                    "source_kind": "public",
                    "primary_plane": plane,
                    "generator_family": None,
                    "scenarios": _scenarios(lineage),
                }
            )
        for family in FAMILIES:
            count = 10 if family == "template" else 6
            for index in range(count):
                lineage = f"generated-{plane}-{family}-{index:02d}"
                rows.append(
                    {
                        "lineage_id": lineage,
                        "source_kind": "generated",
                        "primary_plane": plane,
                        "generator_family": family,
                        "scenarios": _scenarios(lineage),
                    }
                )
    return rows


def _seal(candidates: list[dict]) -> dict:
    return {
        "schema": "k_guard_h100_candidate_seal.v1",
        "sealed_at": "2026-07-18T00:00:00Z",
        "candidate_pool_sha256": candidate_pool_sha256(candidates),
        "candidate_commit_sha256": "a" * 64,
    }


@pytest.fixture(scope="module")
def beacon_identity():
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "K-Guard Test Root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2025, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, selector.NIST_BEACON_DNS_NAME)]
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2025, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(selector.NIST_BEACON_DNS_NAME)]
            ),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    return root, leaf, leaf_key


@pytest.fixture(autouse=True)
def trusted_test_root(monkeypatch, beacon_identity) -> None:
    root, _, _ = beacon_identity
    monkeypatch.setattr(selector, "_trusted_root_certificates", lambda: [root])


def _list_values(previous: str) -> list[dict[str, str]]:
    return [
        {"type": "previous", "value": previous},
        {"type": "hour", "value": "51" * 64},
        {"type": "day", "value": "52" * 64},
        {"type": "month", "value": "53" * 64},
        {"type": "year", "value": "54" * 64},
    ]


def _sign_pulse(pulse: dict, key) -> None:
    signed = selector._pulse_signature_input(pulse)
    signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA512())
    pulse["signatureValue"] = signature.hex().upper()
    pulse["outputValue"] = hashlib.sha512(signed + signature).hexdigest().upper()


def _unsigned_pulse(
    *,
    certificate_id: str,
    index: int,
    timestamp: str,
    local_random: str,
    precommitment: str,
    previous_output: str,
) -> dict:
    return {
        "uri": f"{selector.NIST_BEACON_URI_PREFIX}chain/2/pulse/{index}",
        "version": "2.0",
        "cipherSuite": 0,
        "period": 60_000,
        "certificateId": certificate_id,
        "chainIndex": 2,
        "pulseIndex": index,
        "timeStamp": timestamp,
        "localRandomValue": local_random,
        "external": {
            "sourceId": "00" * 64,
            "statusCode": 0,
            "value": "00" * 64,
        },
        "listValues": _list_values(previous_output),
        "precommitmentValue": precommitment,
        "statusCode": 0,
        "signatureValue": "00",
        "outputValue": "00" * 64,
    }


def _receipt(
    beacon_identity,
    *,
    pulse_time: str = "2026-07-18T00:10:00Z",
    previous_time: str = "2026-07-18T00:09:00Z",
) -> dict:
    root, leaf, key = beacon_identity
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    root_der = root.public_bytes(serialization.Encoding.DER)
    certificate_id = hashlib.sha512(leaf_der).hexdigest()
    current_local = "12" * 64
    previous = _unsigned_pulse(
        certificate_id=certificate_id,
        index=100,
        timestamp=previous_time,
        local_random="34" * 64,
        precommitment=hashlib.sha512(bytes.fromhex(current_local)).hexdigest(),
        previous_output="45" * 64,
    )
    _sign_pulse(previous, key)
    pulse = _unsigned_pulse(
        certificate_id=certificate_id,
        index=101,
        timestamp=pulse_time,
        local_random=current_local,
        precommitment="56" * 64,
        previous_output=previous["outputValue"],
    )
    _sign_pulse(pulse, key)
    return {
        "schema": "k_guard_nist_beacon_verified_receipt.v2",
        "pulse": pulse,
        "previous_pulse": previous,
        "certificates": {
            certificate_id: {
                "leaf_pem": leaf.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                "intermediates_pem": [],
                "trust_anchor_sha256": hashlib.sha256(root_der).hexdigest(),
            }
        },
    }


def test_h100_selection_is_deterministic_and_satisfies_locked_contract(
    beacon_identity,
) -> None:
    candidates = _candidate_pool()
    first = select_h100(
        candidate_seal=_seal(candidates),
        beacon_receipt=_receipt(beacon_identity),
        candidates=candidates,
    )
    second = select_h100(
        candidate_seal=_seal(list(reversed(candidates))),
        beacon_receipt=_receipt(beacon_identity),
        candidates=list(reversed(candidates)),
    )

    assert first.seed_sha256 == second.seed_sha256
    assert [row["lineage_id"] for row in first.selected] == [
        row["lineage_id"] for row in second.selected
    ]
    assert len(first.selected) == 100
    assert sum(row["source_kind"] == "generated" for row in first.selected) == 80
    assert sum(row["source_kind"] == "public" for row in first.selected) == 20
    assert {
        family: sum(row["generator_family"] == family for row in first.selected)
        for family in FAMILIES
    } == GENERATOR_QUOTAS
    assert all(
        counts
        == {
            "lineages": 25,
            "generated": 20,
            "public": 5,
            "positive": 100,
            "negative": 100,
            "critical_positive": 25,
        }
        for counts in first.scenario_counts.values()
    )
    assert first.cryptographic_verification_performed_by_module is True
    assert "system_trust_verified" in first.verification_boundary


@pytest.mark.parametrize(
    ("mutate", "error"),
    [
        (
            lambda receipt: receipt["pulse"].update({"signatureValue": "00" * 256}),
            "beacon_signature_invalid",
        ),
        (
            lambda receipt: receipt["pulse"].update({"outputValue": "ff" * 64}),
            "beacon_output_value_invalid",
        ),
        (
            lambda receipt: next(iter(receipt["certificates"].values())).update(
                {"trust_anchor_sha256": "f" * 64}
            ),
            "beacon_trust_anchor_mismatch",
        ),
    ],
)
def test_beacon_cryptographic_proof_fails_closed(
    beacon_identity, mutate, error: str
) -> None:
    candidates = _candidate_pool()
    receipt = _receipt(beacon_identity)
    mutate(receipt)
    with pytest.raises(H100ContractError, match=error):
        select_h100(
            candidate_seal=_seal(candidates),
            beacon_receipt=receipt,
            candidates=candidates,
        )


def test_beacon_chain_and_candidate_seal_are_bound(beacon_identity) -> None:
    candidates = _candidate_pool()
    receipt = _receipt(beacon_identity)
    _, _, key = beacon_identity
    receipt["pulse"]["listValues"][0]["value"] = "aa" * 64
    _sign_pulse(receipt["pulse"], key)
    with pytest.raises(H100ContractError, match="previous_output_chain_mismatch"):
        select_h100(
            candidate_seal=_seal(candidates),
            beacon_receipt=receipt,
            candidates=candidates,
        )

    seal = _seal(candidates)
    seal["candidate_pool_sha256"] = "f" * 64
    with pytest.raises(H100ContractError, match="candidate_pool_not_bound_to_seal"):
        select_h100(
            candidate_seal=seal,
            beacon_receipt=_receipt(beacon_identity),
            candidates=candidates,
        )


def test_first_post_delay_pulse_and_24_hour_boundary_are_required(
    beacon_identity,
) -> None:
    candidates = _candidate_pool()
    with pytest.raises(
        H100ContractError,
        match="beacon_pulse_before_candidate_seal_plus_10_minutes",
    ):
        select_h100(
            candidate_seal=_seal(candidates),
            beacon_receipt=_receipt(
                beacon_identity,
                pulse_time="2026-07-18T00:09:59Z",
                previous_time="2026-07-18T00:08:59Z",
            ),
            candidates=candidates,
        )

    with pytest.raises(
        H100ContractError,
        match="beacon_pulse_not_first_verified_pulse_after_eligibility",
    ):
        select_h100(
            candidate_seal=_seal(candidates),
            beacon_receipt=_receipt(
                beacon_identity,
                pulse_time="2026-07-18T00:11:00Z",
                previous_time="2026-07-18T00:10:00Z",
            ),
            candidates=candidates,
        )

    eligible = datetime(2026, 7, 18, 0, 10, tzinfo=UTC)
    with pytest.raises(H100ContractError, match="within_24_hours"):
        select_h100(
            candidate_seal=_seal(candidates),
            beacon_receipt=_receipt(
                beacon_identity,
                pulse_time=(eligible + timedelta(hours=24, seconds=1)).isoformat(),
                previous_time="2026-07-18T00:09:00Z",
            ),
            candidates=candidates,
        )


def test_duplicate_lineage_and_insufficient_mix_or_scenarios_fail_closed(
    beacon_identity,
) -> None:
    candidates = _candidate_pool()
    duplicate = copy.deepcopy(candidates)
    duplicate.append(copy.deepcopy(duplicate[0]))
    with pytest.raises(H100ContractError, match="duplicate_lineage_id"):
        candidate_pool_sha256(duplicate)

    insufficient_mix = [
        row
        for row in candidates
        if not (
            row["primary_plane"] == "site"
            and row["generator_family"] == "grok"
            and row["lineage_id"].endswith(("03", "04", "05"))
        )
    ]
    with pytest.raises(
        H100ContractError, match="insufficient_generated_candidates:site:grok"
    ):
        select_h100(
            candidate_seal=_seal(insufficient_mix),
            beacon_receipt=_receipt(beacon_identity),
            candidates=insufficient_mix,
        )

    insufficient_scenarios = copy.deepcopy(candidates)
    for row in insufficient_scenarios:
        if row["primary_plane"] == "data":
            row["scenarios"] = row["scenarios"][:6]
    with pytest.raises(
        H100ContractError, match="h100_positive_scenarios_insufficient:data"
    ):
        select_h100(
            candidate_seal=_seal(insufficient_scenarios),
            beacon_receipt=_receipt(beacon_identity),
            candidates=insufficient_scenarios,
        )


def test_pulse_digest_is_bound_to_official_shape(beacon_identity) -> None:
    receipt = _receipt(beacon_identity)
    assert beacon_pulse_sha256(receipt) == selector.canonical_sha256(receipt["pulse"])
