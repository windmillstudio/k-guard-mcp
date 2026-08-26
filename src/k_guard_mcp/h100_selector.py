from __future__ import annotations

import hashlib
import json
import re
import ssl
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping, Sequence


PLANES = ("site", "api", "data", "operations")
GENERATOR_FAMILIES = ("template", "codex", "claude", "grok")
GENERATOR_QUOTAS = {"template": 32, "codex": 16, "claude": 16, "grok": 16}
PER_PLANE_GENERATOR_QUOTAS = {"template": 8, "codex": 4, "claude": 4, "grok": 4}
PUBLIC_PER_PLANE = 5
MIN_POSITIVE_PER_PLANE = 100
MIN_NEGATIVE_PER_PLANE = 100
MIN_CRITICAL_PER_PLANE = 25
MIN_BEACON_DELAY = timedelta(minutes=10)
MAX_BEACON_WAIT = timedelta(hours=24)
NIST_BEACON_DNS_NAME = "engine.beacon.nist.gov"
NIST_BEACON_URI_PREFIX = "https://beacon.nist.gov/beacon/2.0/"
NIST_BEACON_PERIOD_MS = 60_000

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_HEX_512_RE = re.compile(r"[0-9a-fA-F]{128}\Z")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})+\Z")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_LIST_VALUE_TYPES = ("previous", "hour", "day", "month", "year")


class H100ContractError(ValueError):
    """Raised when the sealed H100 selection contract cannot be proven."""


@dataclass(frozen=True)
class H100Selection:
    seed_sha256: str
    candidate_seal_sha256: str
    candidate_pool_sha256: str
    beacon_pulse_sha256: str
    selected: tuple[dict[str, Any], ...]
    scenario_counts: dict[str, dict[str, int]]
    verification_boundary: str = (
        "nist_v2_signature_output_chain_and_system_trust_verified_in_process_v1"
    )
    cryptographic_verification_performed_by_module: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "k_guard_h100_selection.v2",
            "passed": True,
            "fail_closed": True,
            "seed_sha256": self.seed_sha256,
            "candidate_seal_sha256": self.candidate_seal_sha256,
            "candidate_pool_sha256": self.candidate_pool_sha256,
            "beacon_pulse_sha256": self.beacon_pulse_sha256,
            "selected": [dict(item) for item in self.selected],
            "scenario_counts": self.scenario_counts,
            "verification_boundary": self.verification_boundary,
            "cryptographic_verification_performed_by_module": True,
        }


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def candidate_pool_sha256(candidates: Sequence[Mapping[str, Any]]) -> str:
    normalized = _normalize_candidates(candidates)
    return canonical_sha256(sorted(normalized, key=lambda item: item["lineage_id"]))


def beacon_pulse_sha256(receipt: Mapping[str, Any]) -> str:
    return canonical_sha256(_mapping(receipt.get("pulse"), "beacon pulse"))


def select_h100(
    *,
    candidate_seal: Mapping[str, Any],
    beacon_receipt: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
) -> H100Selection:
    """Verify official NIST evidence and deterministically select H100."""

    normalized = _normalize_candidates(candidates)
    pool_digest = canonical_sha256(
        sorted(normalized, key=lambda item: item["lineage_id"])
    )
    seal_time, seal_digest = _validate_candidate_seal(candidate_seal, pool_digest)
    pulse_time, previous_time, output_value, pulse_digest = _validate_beacon_receipt(
        beacon_receipt
    )
    eligible_at = seal_time + MIN_BEACON_DELAY
    if pulse_time < eligible_at:
        raise H100ContractError("beacon_pulse_before_candidate_seal_plus_10_minutes")
    if previous_time >= eligible_at:
        raise H100ContractError("beacon_pulse_not_first_verified_pulse_after_eligibility")
    if pulse_time > eligible_at + MAX_BEACON_WAIT:
        raise H100ContractError("verified_beacon_pulse_not_available_within_24_hours")

    seed_digest = hashlib.sha256(
        b"k-guard-h100-selector-v2\0"
        + bytes.fromhex(output_value)
        + bytes.fromhex(seal_digest)
    ).hexdigest()
    selected = _select_candidates(normalized, seed_digest)
    counts = _validate_selected_contract(selected)
    return H100Selection(
        seed_sha256=seed_digest,
        candidate_seal_sha256=seal_digest,
        candidate_pool_sha256=pool_digest,
        beacon_pulse_sha256=pulse_digest,
        selected=tuple(selected),
        scenario_counts=counts,
    )


def _validate_candidate_seal(
    seal: Mapping[str, Any], expected_pool_sha256: str
) -> tuple[datetime, str]:
    if seal.get("schema") != "k_guard_h100_candidate_seal.v1":
        raise H100ContractError("candidate_seal_schema_invalid")
    sealed_at = _parse_utc(seal.get("sealed_at"), "candidate sealed_at")
    pool_digest = _sha256(seal.get("candidate_pool_sha256"), "candidate_pool_sha256")
    _sha256(seal.get("candidate_commit_sha256"), "candidate_commit_sha256")
    if pool_digest != expected_pool_sha256:
        raise H100ContractError("candidate_pool_not_bound_to_seal")
    return sealed_at, canonical_sha256(dict(seal))


def _validate_beacon_receipt(
    receipt: Mapping[str, Any],
) -> tuple[datetime, datetime, str, str]:
    if receipt.get("schema") != "k_guard_nist_beacon_verified_receipt.v2":
        raise H100ContractError("beacon_receipt_schema_invalid")
    pulse = _mapping(receipt.get("pulse"), "beacon pulse")
    previous = _mapping(receipt.get("previous_pulse"), "previous beacon pulse")
    certificates = _mapping(receipt.get("certificates"), "beacon certificates")

    pulse_time, output_value, pulse_values = _verify_official_pulse(
        pulse, certificates
    )
    previous_time, previous_output, previous_values = _verify_official_pulse(
        previous, certificates
    )
    chain_index = _integer(pulse.get("chainIndex"), "beacon chainIndex", minimum=1)
    previous_chain_index = _integer(
        previous.get("chainIndex"), "previous beacon chainIndex", minimum=1
    )
    pulse_index = _integer(pulse.get("pulseIndex"), "beacon pulseIndex", minimum=2)
    previous_index = _integer(
        previous.get("pulseIndex"), "previous beacon pulseIndex", minimum=1
    )
    if chain_index != previous_chain_index or pulse_index != previous_index + 1:
        raise H100ContractError("beacon_chain_index_or_sequence_invalid")
    if previous_time >= pulse_time:
        raise H100ContractError("beacon_chain_time_order_invalid")
    if pulse_values["previous"].casefold() != previous_output:
        raise H100ContractError("beacon_previous_output_chain_mismatch")
    expected_precommitment = hashlib.sha512(
        bytes.fromhex(str(pulse["localRandomValue"]))
    ).hexdigest()
    if expected_precommitment != str(previous["precommitmentValue"]).casefold():
        raise H100ContractError("beacon_precommitment_chain_mismatch")
    if previous_values["previous"].casefold() == previous_output:
        raise H100ContractError("previous_beacon_self_chain_invalid")
    return pulse_time, previous_time, output_value, canonical_sha256(pulse)


def _verify_official_pulse(
    pulse: Mapping[str, Any], certificates: Mapping[str, Any]
) -> tuple[datetime, str, dict[str, str]]:
    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
    except ImportError as exc:
        raise H100ContractError("beacon_cryptographic_verifier_unavailable") from exc

    version = pulse.get("version")
    if version != "2.0":
        raise H100ContractError("beacon_version_invalid")
    cipher_suite = _integer(pulse.get("cipherSuite"), "beacon cipherSuite", minimum=0)
    if cipher_suite != 0:
        raise H100ContractError("beacon_cipher_suite_unsupported")
    if _integer(pulse.get("period"), "beacon period", minimum=1) != NIST_BEACON_PERIOD_MS:
        raise H100ContractError("beacon_period_invalid")
    chain_index = _integer(pulse.get("chainIndex"), "beacon chainIndex", minimum=1)
    pulse_index = _integer(pulse.get("pulseIndex"), "beacon pulseIndex", minimum=1)
    expected_uri = f"{NIST_BEACON_URI_PREFIX}chain/{chain_index}/pulse/{pulse_index}"
    if pulse.get("uri") != expected_uri:
        raise H100ContractError("beacon_uri_invalid")
    pulse_time = _parse_utc(pulse.get("timeStamp"), "beacon timeStamp")
    certificate_id = _hex_512(pulse.get("certificateId"), "beacon certificateId")
    _hex_512(pulse.get("localRandomValue"), "beacon localRandomValue")
    _hex_512(pulse.get("precommitmentValue"), "beacon precommitmentValue")
    output_value = _hex_512(pulse.get("outputValue"), "beacon outputValue").casefold()
    signature_value = _hex(pulse.get("signatureValue"), "beacon signatureValue")
    if _integer(pulse.get("statusCode"), "beacon statusCode", minimum=0) != 0:
        raise H100ContractError("beacon_status_not_success")
    external = _mapping(pulse.get("external"), "beacon external")
    _hex_512(external.get("sourceId"), "beacon external sourceId")
    _integer(external.get("statusCode"), "beacon external statusCode", minimum=0)
    _hex_512(external.get("value"), "beacon external value")
    list_values = _list_values(pulse.get("listValues"))

    certificate_entry = _mapping(
        certificates.get(certificate_id), "beacon certificate entry"
    )
    leaf_pem = certificate_entry.get("leaf_pem")
    intermediates_pem = certificate_entry.get("intermediates_pem")
    trust_anchor_sha256 = _sha256(
        certificate_entry.get("trust_anchor_sha256"), "trust_anchor_sha256"
    )
    if not isinstance(leaf_pem, str) or not leaf_pem.startswith("-----BEGIN CERTIFICATE-----"):
        raise H100ContractError("beacon_leaf_certificate_invalid")
    if (
        not isinstance(intermediates_pem, Sequence)
        or isinstance(intermediates_pem, (str, bytes))
        or not all(isinstance(item, str) for item in intermediates_pem)
    ):
        raise H100ContractError("beacon_intermediate_certificates_invalid")
    try:
        leaf = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))
        intermediates = [
            x509.load_pem_x509_certificate(item.encode("ascii"))
            for item in intermediates_pem
        ]
        leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    except (ValueError, UnicodeEncodeError) as exc:
        raise H100ContractError("beacon_certificate_parse_failed") from exc
    if hashlib.sha512(leaf_der).hexdigest() != certificate_id.casefold():
        raise H100ContractError("beacon_certificate_id_mismatch")

    roots = _trusted_root_certificates()
    if not roots:
        raise H100ContractError("beacon_system_trust_store_empty")
    try:
        verifier = (
            PolicyBuilder()
            .store(Store(roots))
            .time(pulse_time)
            .max_chain_depth(6)
            .build_server_verifier(x509.DNSName(NIST_BEACON_DNS_NAME))
        )
        verified_chain = verifier.verify(leaf, intermediates)
    except (VerificationError, ValueError) as exc:
        raise H100ContractError("beacon_certificate_path_invalid") from exc
    if not verified_chain:
        raise H100ContractError("beacon_certificate_path_empty")
    anchor_der = verified_chain[-1].public_bytes(serialization.Encoding.DER)
    if hashlib.sha256(anchor_der).hexdigest() != trust_anchor_sha256:
        raise H100ContractError("beacon_trust_anchor_mismatch")

    public_key = leaf.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise H100ContractError("beacon_signature_key_not_rsa")
    signature = bytes.fromhex(signature_value)
    if len(signature) != (public_key.key_size + 7) // 8:
        raise H100ContractError("beacon_signature_length_invalid")
    signed_message = _pulse_signature_input(pulse)
    try:
        public_key.verify(
            signature,
            signed_message,
            padding.PKCS1v15(),
            hashes.SHA512(),
        )
    except InvalidSignature as exc:
        raise H100ContractError("beacon_signature_invalid") from exc
    expected_output = hashlib.sha512(signed_message + signature).hexdigest()
    if expected_output != output_value:
        raise H100ContractError("beacon_output_value_invalid")
    return pulse_time, output_value, list_values


def _trusted_root_certificates() -> list[Any]:
    try:
        from cryptography import x509
        from cryptography.utils import CryptographyDeprecationWarning
    except ImportError as exc:
        raise H100ContractError("beacon_cryptographic_verifier_unavailable") from exc
    context = ssl.create_default_context()
    roots: list[Any] = []
    for raw in context.get_ca_certs(binary_form=True):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", CryptographyDeprecationWarning)
                roots.append(x509.load_der_x509_certificate(raw))
        except ValueError:
            continue
    return roots


def _pulse_signature_input(pulse: Mapping[str, Any]) -> bytes:
    fields: list[bytes] = []

    def text(value: Any, name: str) -> None:
        if not isinstance(value, str) or not value:
            raise H100ContractError(f"{name}_invalid")
        raw = value.encode("utf-8")
        fields.extend((len(value).to_bytes(4, "big"), raw))

    def integer(value: Any, name: str, width: int) -> None:
        parsed = _integer(value, name, minimum=0)
        try:
            fields.append(parsed.to_bytes(width, "big"))
        except OverflowError as exc:
            raise H100ContractError(f"{name}_out_of_range") from exc

    def hexadecimal(value: Any, name: str) -> None:
        raw = bytes.fromhex(_hex(value, name))
        fields.extend((len(raw).to_bytes(4, "big"), raw))

    text(pulse.get("uri"), "beacon uri")
    text(pulse.get("version"), "beacon version")
    integer(pulse.get("cipherSuite"), "beacon cipherSuite", 4)
    integer(pulse.get("period"), "beacon period", 4)
    hexadecimal(pulse.get("certificateId"), "beacon certificateId")
    integer(pulse.get("chainIndex"), "beacon chainIndex", 8)
    integer(pulse.get("pulseIndex"), "beacon pulseIndex", 8)
    text(pulse.get("timeStamp"), "beacon timeStamp")
    hexadecimal(pulse.get("localRandomValue"), "beacon localRandomValue")
    external = _mapping(pulse.get("external"), "beacon external")
    hexadecimal(external.get("sourceId"), "beacon external sourceId")
    integer(external.get("statusCode"), "beacon external statusCode", 4)
    hexadecimal(external.get("value"), "beacon external value")
    for item in _list_value_rows(pulse.get("listValues")):
        hexadecimal(item["value"], f"beacon listValue {item['type']}")
    hexadecimal(pulse.get("precommitmentValue"), "beacon precommitmentValue")
    integer(pulse.get("statusCode"), "beacon statusCode", 4)
    return b"".join(fields)


def _list_value_rows(value: Any) -> list[Mapping[str, Any]]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or len(value) != len(_LIST_VALUE_TYPES)
    ):
        raise H100ContractError("beacon_list_values_invalid")
    rows = [_mapping(item, "beacon listValue") for item in value]
    if tuple(item.get("type") for item in rows) != _LIST_VALUE_TYPES:
        raise H100ContractError("beacon_list_value_order_invalid")
    return rows


def _list_values(value: Any) -> dict[str, str]:
    return {
        str(item["type"]): _hex_512(
            item.get("value"), f"beacon listValue {item['type']}"
        )
        for item in _list_value_rows(value)
    }


def _normalize_candidates(
    candidates: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if isinstance(candidates, (str, bytes)) or not isinstance(candidates, Sequence):
        raise H100ContractError("candidate_pool_must_be_a_sequence")
    normalized: list[dict[str, Any]] = []
    lineage_ids: set[str] = set()
    for index, raw in enumerate(candidates):
        item = _mapping(raw, f"candidate[{index}]")
        lineage_id = _identifier(item.get("lineage_id"), f"candidate[{index}].lineage_id")
        if lineage_id in lineage_ids:
            raise H100ContractError(f"duplicate_lineage_id:{lineage_id}")
        lineage_ids.add(lineage_id)
        source_kind = item.get("source_kind")
        if source_kind not in {"generated", "public"}:
            raise H100ContractError(f"candidate_source_kind_invalid:{lineage_id}")
        plane = item.get("primary_plane")
        if plane not in PLANES:
            raise H100ContractError(f"candidate_primary_plane_invalid:{lineage_id}")
        generator_family = item.get("generator_family")
        if source_kind == "generated" and generator_family not in GENERATOR_FAMILIES:
            raise H100ContractError(f"candidate_generator_family_invalid:{lineage_id}")
        if source_kind == "public" and generator_family not in (None, ""):
            raise H100ContractError(f"public_candidate_has_generator_family:{lineage_id}")
        normalized.append(
            {
                "lineage_id": lineage_id,
                "source_kind": source_kind,
                "primary_plane": plane,
                "generator_family": generator_family or None,
                "scenarios": _normalize_scenarios(item.get("scenarios"), lineage_id),
            }
        )
    return normalized


def _normalize_scenarios(raw: Any, lineage_id: str) -> list[dict[str, str]]:
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence) or not raw:
        raise H100ContractError(f"candidate_scenarios_missing:{lineage_id}")
    scenarios: list[dict[str, str]] = []
    scenario_ids: set[str] = set()
    root_keys: set[tuple[str, str]] = set()
    for index, value in enumerate(raw):
        scenario = _mapping(value, f"scenario[{index}] for {lineage_id}")
        scenario_id = _identifier(scenario.get("scenario_id"), "scenario_id")
        root_cause_id = _identifier(scenario.get("root_cause_id"), "root_cause_id")
        kind = scenario.get("kind")
        severity = scenario.get("severity")
        if kind not in {"positive", "negative"}:
            raise H100ContractError(f"scenario_kind_invalid:{lineage_id}:{scenario_id}")
        if kind == "positive" and severity not in {"high", "critical"}:
            raise H100ContractError(f"positive_scenario_severity_invalid:{lineage_id}:{scenario_id}")
        if kind == "negative" and severity != "none":
            raise H100ContractError(f"negative_scenario_severity_invalid:{lineage_id}:{scenario_id}")
        if scenario_id in scenario_ids:
            raise H100ContractError(f"duplicate_scenario_id:{lineage_id}:{scenario_id}")
        root_key = (kind, root_cause_id)
        if root_key in root_keys:
            raise H100ContractError(f"duplicate_root_cause:{lineage_id}:{kind}:{root_cause_id}")
        scenario_ids.add(scenario_id)
        root_keys.add(root_key)
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "root_cause_id": root_cause_id,
                "kind": kind,
                "severity": severity,
            }
        )
    return sorted(scenarios, key=lambda item: item["scenario_id"])


def _select_candidates(
    candidates: list[dict[str, Any]], seed_sha256: str
) -> list[dict[str, Any]]:
    seed = bytes.fromhex(seed_sha256)

    def ranked(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            rows,
            key=lambda item: (
                hashlib.sha256(seed + b"\0" + item["lineage_id"].encode("ascii")).digest(),
                item["lineage_id"],
            ),
        )

    selected: list[dict[str, Any]] = []
    for plane in PLANES:
        public = [
            item
            for item in candidates
            if item["primary_plane"] == plane and item["source_kind"] == "public"
        ]
        if len(public) < PUBLIC_PER_PLANE:
            raise H100ContractError(f"insufficient_public_candidates:{plane}")
        selected.extend(ranked(public)[:PUBLIC_PER_PLANE])
        for family, quota in PER_PLANE_GENERATOR_QUOTAS.items():
            generated = [
                item
                for item in candidates
                if item["primary_plane"] == plane
                and item["source_kind"] == "generated"
                and item["generator_family"] == family
            ]
            if len(generated) < quota:
                raise H100ContractError(
                    f"insufficient_generated_candidates:{plane}:{family}"
                )
            selected.extend(ranked(generated)[:quota])
    return sorted(selected, key=lambda item: item["lineage_id"])


def _validate_selected_contract(
    selected: list[dict[str, Any]],
) -> dict[str, dict[str, int]]:
    if len(selected) != 100 or len({item["lineage_id"] for item in selected}) != 100:
        raise H100ContractError("h100_size_or_lineage_uniqueness_invalid")
    if sum(item["source_kind"] == "generated" for item in selected) != 80:
        raise H100ContractError("h100_generated_count_invalid")
    if sum(item["source_kind"] == "public" for item in selected) != 20:
        raise H100ContractError("h100_public_count_invalid")
    for family, quota in GENERATOR_QUOTAS.items():
        if sum(item["generator_family"] == family for item in selected) != quota:
            raise H100ContractError(f"h100_generator_mix_invalid:{family}")

    counts: dict[str, dict[str, int]] = {}
    for plane in PLANES:
        rows = [item for item in selected if item["primary_plane"] == plane]
        generated = sum(item["source_kind"] == "generated" for item in rows)
        public = sum(item["source_kind"] == "public" for item in rows)
        positive = sum(
            scenario["kind"] == "positive"
            for item in rows
            for scenario in item["scenarios"]
        )
        negative = sum(
            scenario["kind"] == "negative"
            for item in rows
            for scenario in item["scenarios"]
        )
        critical = sum(
            scenario["kind"] == "positive" and scenario["severity"] == "critical"
            for item in rows
            for scenario in item["scenarios"]
        )
        counts[plane] = {
            "lineages": len(rows),
            "generated": generated,
            "public": public,
            "positive": positive,
            "negative": negative,
            "critical_positive": critical,
        }
        if len(rows) != 25 or generated != 20 or public != 5:
            raise H100ContractError(f"h100_plane_mix_invalid:{plane}")
        if positive < MIN_POSITIVE_PER_PLANE:
            raise H100ContractError(f"h100_positive_scenarios_insufficient:{plane}")
        if negative < MIN_NEGATIVE_PER_PLANE:
            raise H100ContractError(f"h100_negative_scenarios_insufficient:{plane}")
        if critical < MIN_CRITICAL_PER_PLANE:
            raise H100ContractError(f"h100_critical_scenarios_insufficient:{plane}")
    return counts


def _parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise H100ContractError(f"{field}_missing")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise H100ContractError(f"{field}_invalid") from exc
    if parsed.tzinfo is None:
        raise H100ContractError(f"{field}_timezone_missing")
    return parsed.astimezone(UTC)


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise H100ContractError(f"{field}_must_be_an_object")
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise H100ContractError(f"{field}_invalid")
    return value


def _integer(value: Any, field: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise H100ContractError(f"{field}_invalid")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value.casefold()) is None:
        raise H100ContractError(f"{field}_invalid")
    return value.casefold()


def _hex_512(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX_512_RE.fullmatch(value) is None:
        raise H100ContractError(f"{field}_invalid")
    return value


def _hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX_RE.fullmatch(value) is None:
        raise H100ContractError(f"{field}_invalid")
    return value
