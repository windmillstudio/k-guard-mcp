from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
import venv
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "holdout_scan_launcher.py"
SOURCE_SCRIPT = ROOT / "scripts" / "holdout_source_materialization.py"
SPEC = importlib.util.spec_from_file_location("holdout_scan_launcher_test", SCRIPT)
assert SPEC and SPEC.loader
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)
SOURCE_SPEC = importlib.util.spec_from_file_location(
    "holdout_source_materialization_launcher_test", SOURCE_SCRIPT
)
assert SOURCE_SPEC and SOURCE_SPEC.loader
source_materialization = importlib.util.module_from_spec(SOURCE_SPEC)
SOURCE_SPEC.loader.exec_module(source_materialization)

# One launcher run contains up to 112 seconds of independent bounded watcher,
# drain, join, and defensive cleanup waits before synchronous scan/attestation
# work. Allow extra Windows CPython 3.13/3.14 shared-runner startup and scan
# time; production guard bounds and every terminal/fail-closed assertion remain.
LAUNCH_PROCESS_TIMEOUT_SECONDS = 600


def test_code_object_control_accepts_shifted_importlib_loader_frame_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeFrame:
        def __init__(
            self,
            filename: str,
            function: str,
            back: "FakeFrame | None" = None,
            *,
            code: object | None = None,
        ) -> None:
            self.f_code = code or type(
                "FakeCode",
                (),
                {"co_filename": filename, "co_name": function},
            )()
            self.f_back = back

    trusted_loader_code = launcher.importlib._bootstrap_external._compile_bytecode.__code__
    loader = FakeFrame(
        "<frozen importlib._bootstrap_external>",
        "_compile_bytecode",
        code=trusted_loader_code,
    )
    shifted = loader
    for index in range(10):
        shifted = FakeFrame("<frozen marshal>", f"loads_{index}", shifted)
    audit = object.__new__(launcher._ExecutionAudit)
    audit._errors = set()
    audit._code_object_events = {}
    audit._dynamic = set()
    audit._last_violation = "unknown"
    audit._trusted_importlib_compile_bytecode_sha256 = {
        launcher._code_object_sha256(trusted_loader_code)
    }
    audit._trusted_marshaled_pyc_sha256 = set()
    audit._caller_frames = lambda: []

    with monkeypatch.context() as patch:
        patch.setattr(sys, "_getframe", lambda _depth: shifted)
        allowed = audit._record_code_object_control("marshal.loads", (b"attested-pyc",))
    assert allowed is True
    assert next(iter(audit._code_object_events.values()))["allowed_reason"] == (
        "frozen_importlib_bytecode_loader"
    )

    untrusted = FakeFrame(
        "<frozen importlib._bootstrap_external>",
        "_compile_bytecode",
    )
    with monkeypatch.context() as patch:
        patch.setattr(sys, "_getframe", lambda _depth: untrusted)
        allowed = audit._record_code_object_control("marshal.loads", (b"dynamic-code",))
    assert allowed is False
    assert audit._dynamic


def test_code_object_control_accepts_structurally_identical_frozen_loader_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_loader_code = launcher.importlib._bootstrap_external._compile_bytecode.__code__
    copied_loader_code = trusted_loader_code.replace()
    assert copied_loader_code is not trusted_loader_code

    class FakeFrame:
        f_code = copied_loader_code
        f_back = None

    audit = object.__new__(launcher._ExecutionAudit)
    audit._errors = set()
    audit._code_object_events = {}
    audit._dynamic = set()
    audit._last_violation = "unknown"
    audit._trusted_importlib_compile_bytecode_sha256 = {
        launcher._code_object_sha256(trusted_loader_code)
    }
    audit._trusted_marshaled_pyc_sha256 = set()
    audit._caller_frames = lambda: []

    with monkeypatch.context() as patch:
        patch.setattr(sys, "_getframe", lambda _depth: FakeFrame())
        allowed = audit._record_code_object_control("marshal.loads", (b"attested-pyc",))

    assert allowed is True
    assert next(iter(audit._code_object_events.values()))["allowed_reason"] == (
        "frozen_importlib_bytecode_loader"
    )

    altered_loader_code = trusted_loader_code.replace(
        co_consts=trusted_loader_code.co_consts + ("untrusted-structural-change",)
    )

    class AlteredFrame:
        f_code = altered_loader_code
        f_back = None

    with monkeypatch.context() as patch:
        patch.setattr(sys, "_getframe", lambda _depth: AlteredFrame())
        allowed = audit._record_code_object_control("marshal.loads", (b"dynamic-code",))

    assert allowed is False
    assert audit._dynamic


def test_execution_audit_seeds_live_importlib_loader_without_frozen_walk(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "prefix"
    base_prefix = tmp_path / "base"
    windows_root = tmp_path / "windows"
    for root in (prefix, base_prefix, windows_root):
        root.mkdir()

    marshalled_payload = b"preexisting-attested-pyc-payload"
    pycache = prefix / "Lib" / "site-packages" / "example" / "__pycache__"
    pycache.mkdir(parents=True)
    (pycache / "module.cpython-test.pyc").write_bytes(
        launcher.importlib.util.MAGIC_NUMBER + b"\0" * 12 + marshalled_payload
    )
    unlisted_payload = b"unlisted-pyc-payload"
    (pycache / "unlisted.cpython-test.pyc").write_bytes(
        launcher.importlib.util.MAGIC_NUMBER + b"\0" * 12 + unlisted_payload
    )

    with monkeypatch.context() as patch:
        patch.setattr(launcher._imp, "_frozen_module_names", lambda: ())
        audit = launcher._ExecutionAudit(
            prefix,
            base_prefix,
            {
                "prefix_tree": {
                    "files": [
                        {
                            "path": pycache.joinpath(
                                "module.cpython-test.pyc"
                            ).relative_to(prefix).as_posix(),
                            "sha256": hashlib.sha256(
                                launcher.importlib.util.MAGIC_NUMBER
                                + b"\0" * 12
                                + marshalled_payload
                            ).hexdigest(),
                        }
                    ]
                },
                "base_runtime_tree": {"files": []},
            },
            set(),
            windows_root,
            None,
            None,
        )

    live_loader_code = launcher.importlib._bootstrap_external._compile_bytecode.__code__
    assert audit._trusted_importlib_compile_bytecode_sha256 == {
        launcher._code_object_sha256(live_loader_code)
    }
    assert hashlib.sha256(marshalled_payload).hexdigest() in (
        audit._trusted_marshaled_pyc_sha256
    )
    assert hashlib.sha256(unlisted_payload).hexdigest() not in (
        audit._trusted_marshaled_pyc_sha256
    )


def test_code_object_control_allows_only_preexisting_attested_pyc_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_payload = b"preexisting-attested-pyc-payload"
    audit = object.__new__(launcher._ExecutionAudit)
    audit._errors = set()
    audit._code_object_events = {}
    audit._dynamic = set()
    audit._last_violation = "unknown"
    audit._trusted_importlib_compile_bytecode_sha256 = set()
    audit._trusted_marshaled_pyc_sha256 = {hashlib.sha256(trusted_payload).hexdigest()}
    audit._caller_frames = lambda: []

    class FakeCode:
        co_filename = "<redacted loader>"
        co_name = "<module>"

    class FakeFrame:
        f_code = FakeCode()
        f_back = None

    with monkeypatch.context() as patch:
        patch.setattr(sys, "_getframe", lambda _depth: FakeFrame())
        allowed = audit._record_code_object_control("marshal.loads", (trusted_payload,))
        blocked = audit._record_code_object_control("marshal.loads", (b"dynamic-code",))

    assert allowed is True
    allowed_row = next(
        row for row in audit._code_object_events.values() if row["allowed"] is True
    )
    assert allowed_row["allowed_reason"] == "attested_preexisting_pyc_payload"
    assert blocked is False
    assert hashlib.sha256(b"dynamic-code").hexdigest() in audit._dynamic


def test_execution_audit_uses_precomputed_frozen_code_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "prefix"
    base_prefix = tmp_path / "base"
    windows_root = tmp_path / "windows"
    for root in (prefix, base_prefix, windows_root):
        root.mkdir()

    audit = launcher._ExecutionAudit(
        prefix,
        base_prefix,
        {"prefix_tree": {"files": []}, "base_runtime_tree": {"files": []}},
        set(),
        windows_root,
        None,
        None,
    )
    live_loader_code = launcher.importlib._bootstrap_external._compile_bytecode.__code__
    assert launcher._code_object_sha256(live_loader_code) in (
        audit._trusted_importlib_compile_bytecode_sha256
    )
    frozen_code = launcher._imp.get_frozen_object("_frozen_importlib_external")
    assert frozen_code.co_filename == "<frozen importlib._bootstrap_external>"

    with monkeypatch.context() as patch:
        patch.setattr(
            launcher._imp,
            "get_frozen_object",
            lambda _name: pytest.fail("audit hook re-read a frozen object"),
        )
        assert audit._record_dynamic(frozen_code) is True


def test_code_constant_contract_supports_python_314_slice_constants() -> None:
    assert launcher._code_constant_contract(slice(1, None, -1)) == {
        "type": "slice",
        "start": {"type": "int", "value": "1"},
        "stop": {"type": "none"},
        "step": {"type": "int", "value": "-1"},
    }


def test_mutation_filter_covers_writes_and_metadata_without_last_access_noise() -> None:
    assert launcher.MUTATION_NOTIFY_FILTER & launcher.FILE_NOTIFY_CHANGE_LAST_WRITE
    assert launcher.MUTATION_NOTIFY_FILTER & launcher.FILE_NOTIFY_CHANGE_ATTRIBUTES
    assert launcher.MUTATION_NOTIFY_FILTER & launcher.FILE_NOTIFY_CHANGE_CREATION
    assert launcher.MUTATION_NOTIFY_FILTER & launcher.FILE_NOTIFY_CHANGE_SECURITY
    assert launcher.MUTATION_NOTIFY_FILTER & 0x00000020 == 0


@pytest.mark.skipif(sys.platform != "win32", reason="native runtime locks are Windows-specific")
def test_native_runtime_lock_denies_write_and_delete_until_classification(
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "prefix"
    base = tmp_path / "base"
    prefix.mkdir()
    base.mkdir()
    native = prefix / "binding.pyd"
    native.write_bytes(b"attested-native")
    digest = hashlib.sha256(native.read_bytes()).hexdigest()
    expected_runtime = {
        "prefix_tree": {
            "files": [{"path": "binding.pyd", "sha256": digest}],
        },
        "base_runtime_tree": {"files": []},
    }

    guard = launcher._WindowsNativeRuntimeLock(expected_runtime, prefix, base)
    assert guard.start() is True
    try:
        with pytest.raises(OSError):
            native.write_bytes(b"transient-replacement")
        with pytest.raises(OSError):
            native.unlink()
        guard.mark_classification_completed()
    finally:
        guard.stop()

    receipt = guard.receipt()
    assert receipt["passed"] is True
    assert receipt["locked_file_count"] == 1
    assert receipt["released_file_count"] == 1
    assert [row["access"] for row in receipt["metadata_access_canaries"]] == [
        "file_write_attributes",
        "write_dac",
        "write_owner",
        "access_system_security",
    ]
    assert receipt["metadata_integrity_guard"] == (
        launcher.RUNTIME_OBJECT_ATTESTATION_GUARD
    )
    assert native.read_bytes() == b"attested-native"


@pytest.mark.skipif(sys.platform != "win32", reason="native image prewarm is Windows-specific")
def test_native_runtime_prewarm_makes_real_dll_load_notification_free(
    tmp_path: Path,
) -> None:
    from ctypes import wintypes

    system32, *_native_api = launcher._prepare_native_inventory()
    prefix = tmp_path / "prefix"
    base = tmp_path / "base"
    prefix.mkdir()
    base.mkdir()
    native = prefix / "version.dll"
    native.write_bytes((system32 / "version.dll").read_bytes())
    digest = hashlib.sha256(native.read_bytes()).hexdigest()
    expected_runtime = {
        "prefix_tree": {
            "files": [{"path": "version.dll", "sha256": digest}],
        },
        "base_runtime_tree": {"files": []},
    }
    lock = launcher._WindowsNativeRuntimeLock(expected_runtime, prefix, base)
    prewarm = launcher._WindowsNativeRuntimePrewarm(expected_runtime, prefix, base)
    attestation = launcher._WindowsRuntimeObjectAttestation(
        expected_runtime,
        prefix,
        base,
    )
    assert lock.start() is True
    attestation.capture("pre_prewarm")
    assert prewarm.run(native_lock_active=lock.active) is True
    attestation.capture("post_prewarm")
    assert attestation.prewarm_transition_passed is True

    watcher = launcher._WindowsRecursiveWatcher(prefix, "scanner_prefix")
    watcher.start()
    attestation.capture("pre_scan")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LoadLibraryExW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.HANDLE,
        wintypes.DWORD,
    ]
    kernel32.LoadLibraryExW.restype = wintypes.HMODULE
    kernel32.FreeLibrary.argtypes = [wintypes.HMODULE]
    kernel32.FreeLibrary.restype = wintypes.BOOL
    loaded = kernel32.LoadLibraryExW(str(native), None, 0)
    assert loaded
    assert kernel32.FreeLibrary(loaded)
    assert watcher.drain()
    attestation.capture("post_scan")
    assert watcher.drain()
    attestation.capture("post_drain")
    watcher.stop()
    attestation.capture("post_stop")
    attestation.capture("post_classification")
    lock.mark_classification_completed()
    lock.stop()

    prewarm_receipt = prewarm.receipt()
    object_receipt = attestation.receipt()
    assert prewarm_receipt["passed"] is True
    assert prewarm_receipt["mapped_file_count"] == 1
    assert watcher.event_count == 0
    assert object_receipt["passed"] is True
    assert object_receipt["changed_entry_count"] == 0


@pytest.mark.skipif(sys.platform != "win32", reason="runtime object USN attestation is Windows-specific")
def test_runtime_object_attestation_detects_restored_native_metadata(
    tmp_path: Path,
) -> None:
    from ctypes import byref, c_int, sizeof, wintypes

    prefix = tmp_path / "prefix"
    base = tmp_path / "base"
    prefix.mkdir()
    base.mkdir()
    native = prefix / "binding.pyd"
    native.write_bytes(b"attested-native")
    digest = hashlib.sha256(native.read_bytes()).hexdigest()
    expected_runtime = {
        "prefix_tree": {
            "files": [{"path": "binding.pyd", "sha256": digest}],
        },
        "base_runtime_tree": {"files": []},
    }
    attestation = launcher._WindowsRuntimeObjectAttestation(
        expected_runtime,
        prefix,
        base,
    )
    for phase in ("pre_prewarm", "post_prewarm", "pre_scan"):
        attestation.capture(phase)

    kernel32 = attestation._kernel32
    kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    handle = kernel32.CreateFileW(
        str(native),
        launcher.FILE_READ_ATTRIBUTES | launcher.FILE_WRITE_ATTRIBUTES,
        launcher.FILE_SHARE_READ
        | launcher.FILE_SHARE_WRITE
        | launcher.FILE_SHARE_DELETE,
        None,
        launcher.OPEN_EXISTING,
        launcher.FILE_ATTRIBUTE_NORMAL,
        None,
    )
    assert handle != attestation._invalid_handle
    original = attestation._basic_info_type()
    assert kernel32.GetFileInformationByHandleEx(
        handle,
        0,
        byref(original),
        sizeof(original),
    )
    changed = attestation._basic_info_type()
    changed.CreationTime = original.CreationTime
    changed.LastAccessTime = original.LastAccessTime
    changed.LastWriteTime = original.LastWriteTime + 10_000_000
    changed.ChangeTime = original.ChangeTime
    changed.FileAttributes = original.FileAttributes
    assert kernel32.SetFileInformationByHandle(handle, 0, byref(changed), sizeof(changed))
    assert kernel32.SetFileInformationByHandle(
        handle,
        0,
        byref(original),
        sizeof(original),
    )
    assert kernel32.CloseHandle(handle)

    for phase in (
        "post_scan",
        "post_drain",
        "post_stop",
        "post_classification",
    ):
        attestation.capture(phase)

    receipt = attestation.receipt()
    entry = receipt["entries"][0]
    pre = entry["checkpoints"][2]
    final = entry["checkpoints"][-1]
    assert pre["basic_sha256"] == final["basic_sha256"]
    assert pre["security_sha256"] == final["security_sha256"]
    assert pre["file_id_sha256"] == final["file_id_sha256"]
    assert pre["content_sha256"] == final["content_sha256"] == digest
    assert pre["usn_record"]["usn"] != final["usn_record"]["usn"]
    assert receipt["prewarm_transition_passed"] is True
    assert receipt["passed"] is False
    assert receipt["changed_entries"] == ["<prefix>/binding.pyd"]


@pytest.mark.skipif(sys.platform != "win32", reason="runtime ACL attestation is Windows-specific")
def test_runtime_object_attestation_detects_native_acl_write(
    tmp_path: Path,
) -> None:
    from ctypes import wintypes

    prefix = tmp_path / "prefix"
    base = tmp_path / "base"
    prefix.mkdir()
    base.mkdir()
    native = prefix / "binding.pyd"
    native.write_bytes(b"attested-native")
    digest = hashlib.sha256(native.read_bytes()).hexdigest()
    expected_runtime = {
        "prefix_tree": {
            "files": [{"path": "binding.pyd", "sha256": digest}],
        },
        "base_runtime_tree": {"files": []},
    }
    attestation = launcher._WindowsRuntimeObjectAttestation(
        expected_runtime,
        prefix,
        base,
    )
    for phase in ("pre_prewarm", "post_prewarm", "pre_scan"):
        attestation.capture(phase)

    advapi32 = attestation._advapi32
    advapi32.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetFileSecurityW.restype = wintypes.BOOL
    advapi32.SetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    advapi32.SetFileSecurityW.restype = wintypes.BOOL
    security_information = (
        launcher.OWNER_SECURITY_INFORMATION
        | launcher.GROUP_SECURITY_INFORMATION
        | launcher.DACL_SECURITY_INFORMATION
    )
    needed = wintypes.DWORD()
    advapi32.GetFileSecurityW(
        str(native),
        security_information,
        None,
        0,
        ctypes.byref(needed),
    )
    descriptor = ctypes.create_string_buffer(needed.value)
    assert advapi32.GetFileSecurityW(
        str(native),
        security_information,
        descriptor,
        len(descriptor),
        ctypes.byref(needed),
    )
    assert advapi32.SetFileSecurityW(
        str(native),
        security_information,
        descriptor,
    )

    for phase in (
        "post_scan",
        "post_drain",
        "post_stop",
        "post_classification",
    ):
        attestation.capture(phase)

    receipt = attestation.receipt()
    entry = receipt["entries"][0]
    pre = entry["checkpoints"][2]
    final = entry["checkpoints"][-1]
    assert pre["security_sha256"] != final["security_sha256"]
    assert pre["content_sha256"] == final["content_sha256"] == digest
    assert pre["usn_record"]["usn"] != final["usn_record"]["usn"]
    assert receipt["passed"] is False
    assert receipt["changed_entries"] == ["<prefix>/binding.pyd"]


@pytest.mark.skipif(sys.platform != "win32", reason="runtime notification paths are Windows-specific")
def test_runtime_notification_classifier_rejects_every_scan_boundary_event(
    tmp_path: Path,
) -> None:
    protocol = tmp_path / "protocol"
    prefix = protocol / "scanner"
    base = tmp_path / "base"
    prefix.mkdir(parents=True)
    base.mkdir()
    native = prefix / "binding.pyd"
    native.write_bytes(b"attested-native")
    digest = hashlib.sha256(native.read_bytes()).hexdigest()
    expected_runtime = {
        "prefix_tree": {
            "files": [{"path": "binding.pyd", "sha256": digest}],
        },
        "base_runtime_tree": {"files": []},
    }
    notification = {"action": 3, "relative_path": "binding.pyd"}
    image_receipt = {
        "passed": True,
        "events": [
            {
                "action": "load",
                "path": "<prefix>/binding.pyd",
                "sha256": digest,
            }
        ],
    }
    native_attestation = {
        "kind": "native_file",
        "content_sha256": digest,
        "attestation_sha256": "a" * 64,
    }

    classified = launcher._classify_runtime_notifications(
        [
            {
                "root": "scanner_prefix",
                "event_count": 1,
                "events": [notification],
                "error": None,
                "liveness": {"passed": True},
            },
            {
                "root": "protocol_repository",
                "event_count": 1,
                "events": [
                    {
                        "action": 3,
                        "relative_path": "scanner\\binding.pyd",
                    }
                ],
                "error": None,
                "liveness": {"passed": True},
            },
        ],
        {
            "scanner_prefix": prefix,
            "protocol_repository": protocol,
        },
        prefix=prefix,
        base_prefix=base,
        expected_runtime=expected_runtime,
        image_load_receipt=image_receipt,
        locked_native_files={"<prefix>/binding.pyd": digest},
        stable_runtime_objects={"<prefix>/binding.pyd": native_attestation},
        native_lock_active=True,
        object_attestation_checkpoint_passed=True,
        runtime_hashes_match=True,
    )

    assert classified["notification_event_count"] == 2
    assert classified["accepted_native_load_metadata_event_count"] == 0
    assert classified["mutation_event_count"] == 2
    assert classified["runtime_notification_classifier_errors"] == []
    assert all(
        row["accepted_native_load_metadata_events"] == []
        and row["accepted_stable_directory_metadata_events"] == []
        and row["events"] == row["notification_events"]
        for row in classified["mutation_monitors"]
    )

    scripts_dir = prefix / "Scripts"
    scripts_dir.mkdir()
    directory_attestation_hash = "d" * 64
    directory_classified = launcher._classify_runtime_notifications(
        [
            {
                "root": "scanner_prefix",
                "event_count": 1,
                "events": [{"action": 3, "relative_path": "Scripts"}],
                "error": None,
                "liveness": {"passed": True},
            }
        ],
        {"scanner_prefix": prefix},
        prefix=prefix,
        base_prefix=base,
        expected_runtime=expected_runtime,
        image_load_receipt={"passed": True, "events": []},
        locked_native_files={},
        stable_runtime_objects={
            "<prefix>/Scripts": {
                "kind": "directory",
                "content_sha256": None,
                "attestation_sha256": directory_attestation_hash,
            }
        },
        native_lock_active=False,
        object_attestation_checkpoint_passed=True,
        runtime_hashes_match=True,
    )
    assert directory_classified["accepted_native_load_metadata_event_count"] == 0
    assert (
        directory_classified["accepted_stable_directory_metadata_event_count"] == 0
    )
    assert directory_classified["mutation_event_count"] == 1

    rejection_cases = [
        (
            {"action": 3, "relative_path": "module.py"},
            image_receipt,
            {"<prefix>/binding.pyd": digest},
            True,
            True,
        ),
        (
            notification,
            {"passed": True, "events": []},
            {"<prefix>/binding.pyd": digest},
            True,
            True,
        ),
        (
            notification,
            image_receipt,
            {},
            True,
            True,
        ),
        (
            notification,
            image_receipt,
            {"<prefix>/binding.pyd": "0" * 64},
            True,
            True,
        ),
        (
            notification,
            image_receipt,
            {"<prefix>/binding.pyd": digest},
            True,
            False,
        ),
        (
            {"action": 1, "relative_path": "binding.pyd"},
            image_receipt,
            {"<prefix>/binding.pyd": digest},
            True,
            True,
        ),
    ]
    (prefix / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    for event, image, locked, lock_active, hashes_match in rejection_cases:
        rejected = launcher._classify_runtime_notifications(
            [
                {
                    "root": "scanner_prefix",
                    "event_count": 1,
                    "events": [event],
                    "error": None,
                    "liveness": {"passed": True},
                }
            ],
            {"scanner_prefix": prefix},
            prefix=prefix,
            base_prefix=base,
            expected_runtime=expected_runtime,
            image_load_receipt=image,
            locked_native_files=locked,
            stable_runtime_objects={"<prefix>/binding.pyd": native_attestation},
            native_lock_active=lock_active,
            object_attestation_checkpoint_passed=True,
            runtime_hashes_match=hashes_match,
        )
        assert rejected["accepted_native_load_metadata_event_count"] == 0
        assert rejected["mutation_event_count"] == 1

    native.write_bytes(b"hash-mismatch")
    hash_mismatch = launcher._classify_runtime_notifications(
        [
            {
                "root": "scanner_prefix",
                "event_count": 1,
                "events": [notification],
                "error": None,
                "liveness": {"passed": True},
            }
        ],
        {"scanner_prefix": prefix},
        prefix=prefix,
        base_prefix=base,
        expected_runtime=expected_runtime,
        image_load_receipt=image_receipt,
        locked_native_files={"<prefix>/binding.pyd": digest},
        stable_runtime_objects={"<prefix>/binding.pyd": native_attestation},
        native_lock_active=True,
        object_attestation_checkpoint_passed=True,
        runtime_hashes_match=True,
    )
    assert hash_mismatch["accepted_native_load_metadata_event_count"] == 0
    assert hash_mismatch["mutation_event_count"] == 1

    missing_native = launcher._classify_runtime_notifications(
        [
            {
                "root": "scanner_prefix",
                "event_count": 1,
                "events": [{"action": 3, "relative_path": "missing.pyd"}],
                "error": None,
                "liveness": {"passed": True},
            }
        ],
        {"scanner_prefix": prefix},
        prefix=prefix,
        base_prefix=base,
        expected_runtime=expected_runtime,
        image_load_receipt=image_receipt,
        locked_native_files={"<prefix>/binding.pyd": digest},
        stable_runtime_objects={"<prefix>/binding.pyd": native_attestation},
        native_lock_active=True,
        object_attestation_checkpoint_passed=True,
        runtime_hashes_match=True,
    )
    assert missing_native["runtime_notification_classifier_errors"] == []
    assert missing_native["accepted_native_load_metadata_event_count"] == 0
    assert missing_native["mutation_event_count"] == 1


@pytest.mark.skipif(sys.platform != "win32", reason="strict v4 mutation watcher is Windows-specific")
def test_recursive_runtime_watcher_detects_transient_file_change(tmp_path: Path) -> None:
    watched = tmp_path / "runtime"
    watched.mkdir()
    target = watched / "module.py"
    target.write_text("value = 1\n", encoding="utf-8")
    watcher = launcher._WindowsRecursiveWatcher(watched)
    watcher.start()
    try:
        target.write_text("value = 2\n", encoding="utf-8")
        target.write_text("value = 1\n", encoding="utf-8")
        deadline = time.monotonic() + 3
        while not watcher.changed and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        watcher.stop()

    assert watcher.changed is True
    assert watcher.event_count >= 1
    assert watcher.error is None
    assert watcher.liveness["passed"] is True


@pytest.mark.skipif(sys.platform != "win32", reason="strict v4 mutation watcher is Windows-specific")
def test_recursive_runtime_watcher_fails_when_kernel_request_is_cancelled(tmp_path: Path) -> None:
    watched = tmp_path / "runtime"
    watched.mkdir()
    watcher = launcher._WindowsRecursiveWatcher(watched)
    watcher.start()
    assert watcher._kernel32.CancelIoEx(watcher._handle, None)
    deadline = time.monotonic() + 3
    while watcher.error is None and time.monotonic() < deadline:
        time.sleep(0.01)
    watcher.stop()

    assert watcher.changed is True
    assert watcher.error is not None
    assert watcher.liveness["passed"] is False


@pytest.mark.skipif(sys.platform != "win32", reason="native inventory is Windows-specific")
def test_native_inventory_ignores_forged_systemroot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    forged_root = tmp_path / "forged-windows"
    forged_root.mkdir()
    monkeypatch.setenv("SystemRoot", str(forged_root))

    windows_root, *_api = launcher._prepare_native_inventory()

    assert windows_root != forged_root
    assert windows_root.name.casefold() == "system32"
    assert (windows_root / "kernel32.dll").is_file()


@pytest.mark.skipif(sys.platform != "win32", reason="DLL notifications are Windows-specific")
def test_image_monitor_catches_cffi_load_unload_and_delete(tmp_path: Path) -> None:
    cffi = pytest.importorskip("cffi")
    windows_root, *_api = launcher._prepare_native_inventory()
    canary_root = tmp_path / "canary"
    canary_root.mkdir()
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    outside_dll = tmp_path / "outside-version.dll"
    outside_dll.write_bytes((windows_root / "version.dll").read_bytes())
    monitor = launcher._WindowsImageLoadMonitor(windows_root)
    monitor.start()
    try:
        assert monitor.exercise_canary(canary_root, "before-scan") is True
        monitor.begin_scan()
        ffi = cffi.FFI()
        library = ffi.dlopen(str(outside_dll))
        ffi.dlclose(library)
        outside_dll.unlink()
        monitor.end_scan()
        assert monitor.exercise_canary(canary_root, "after-scan") is True
    finally:
        monitor.stop()

    receipt = monitor.receipt(prefix, Path(sys.base_prefix).resolve(), windows_root)
    assert receipt["passed"] is False
    assert receipt["outside_image_events"]
    assert {row["action"] for row in receipt["outside_image_events"]} == {"load", "unload"}
    assert all("path_sha256" in row and "path" not in row for row in receipt["outside_image_events"])


@pytest.mark.skipif(sys.platform != "win32", reason="Windows TCB roots are Windows-specific")
def test_windows_temp_dll_is_not_classified_as_system_tcb(tmp_path: Path) -> None:
    cffi = pytest.importorskip("cffi")
    system32, *_api = launcher._prepare_native_inventory()
    windows_temp = system32.parent / "Temp"
    suffix = hashlib.sha256(str(tmp_path).encode("utf-8")).hexdigest()[:12]
    candidate = windows_temp / f"k-guard-tcb-boundary-{suffix}.dll"
    try:
        candidate.write_bytes((system32 / "version.dll").read_bytes())
    except OSError as exc:
        pytest.skip(f"Windows Temp is not writable in this environment: {type(exc).__name__}")
    canary_root = tmp_path / "canary"
    canary_root.mkdir()
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    monitor = launcher._WindowsImageLoadMonitor(system32)
    monitor.start()
    try:
        assert monitor.exercise_canary(canary_root, "before-scan") is True
        monitor.begin_scan()
        ffi = cffi.FFI()
        library = ffi.dlopen(str(candidate))
        ffi.dlclose(library)
        monitor.end_scan()
        assert monitor.exercise_canary(canary_root, "after-scan") is True
    finally:
        monitor.stop()
        candidate.unlink(missing_ok=True)

    receipt = monitor.receipt(prefix, Path(sys.base_prefix).resolve(), system32)
    assert receipt["passed"] is False
    assert receipt["outside_image_events"]
    assert receipt["events"] == []


@pytest.mark.skipif(sys.platform != "win32", reason="strict v4 mutation watcher is Windows-specific")
def test_launcher_allows_stable_scan_and_rejects_restored_runtime_mutation(tmp_path: Path) -> None:
    protocol_root = tmp_path / "protocol"
    scripts_root = protocol_root / "scripts"
    scripts_root.mkdir(parents=True)
    launcher_path = scripts_root / SCRIPT.name
    launcher_path.write_bytes(SCRIPT.read_bytes())
    source_probe_path = scripts_root / SOURCE_SCRIPT.name
    source_probe_path.write_bytes(
        SOURCE_SCRIPT.read_bytes()
        + b"\n_original_capture_materialized_tree = capture_materialized_tree\n"
        + b"_prehash_swap_done = False\n\n"
        + b"def capture_materialized_tree(root):\n"
        + b"    global _prehash_swap_done\n"
        + b"    result = _original_capture_materialized_tree(root)\n"
        + b"    if os.environ.get('K_GUARD_PREHASH_SOURCE_SWAP') == '1' and not _prehash_swap_done:\n"
        + b"        _prehash_swap_done = True\n"
        + b"        (Path(root) / 'app.py').write_bytes(b\"print('swapped')\\n\")\n"
        + b"    return result\n"
    )
    venv_root = tmp_path / "venv"
    venv.EnvBuilder(with_pip=False).create(venv_root)
    python_path = venv_root / "Scripts" / "python.exe"
    python_hash = hashlib.sha256(python_path.read_bytes()).hexdigest()
    native_canary = venv_root / "native-canary.dll"
    system32, *_native_api = launcher._prepare_native_inventory()
    native_canary.write_bytes((system32 / "version.dll").read_bytes())
    native_canary_hash = hashlib.sha256(native_canary.read_bytes()).hexdigest()
    probe_path = scripts_root / "probe.py"
    base_prefix = Path(sys.base_prefix).resolve()
    base_runtime_pyc_files = []
    for base_pyc in base_prefix.rglob("*.pyc"):
        try:
            resolved_base_pyc = base_pyc.resolve(strict=True)
            if (
                not resolved_base_pyc.is_file()
                or launcher._is_base_site_package(resolved_base_pyc, base_prefix)
            ):
                continue
            base_pyc_bytes = resolved_base_pyc.read_bytes()
        except OSError:
            continue
        base_runtime_pyc_files.append(
            {
                "path": resolved_base_pyc.relative_to(base_prefix).as_posix(),
                "byte_count": len(base_pyc_bytes),
                "sha256": hashlib.sha256(base_pyc_bytes).hexdigest(),
            }
        )
    base_runtime_pyc_files.sort(key=lambda row: row["path"])
    expected_runtime = {
        "schema": launcher.RUNTIME_SCHEMA,
        "test_runtime": "stable",
        "python": {
            "executable_sha256": hashlib.sha256(python_path.read_bytes()).hexdigest(),
            "no_site_flag": 1,
            "manual_site_bootstrap": True,
        },
        "scanner_scaffold": {
            "schema": "k_guard_scanner_venv_scaffold.v1",
            "tree_sha256": "0" * 64,
            "file_count": 0,
            "files": [],
            "raw_returned": False,
        },
        "prefix_tree": {
            "files": [
                {
                    "path": native_canary.relative_to(venv_root).as_posix(),
                    "sha256": native_canary_hash,
                },
                {
                    "path": python_path.relative_to(venv_root).as_posix(),
                    "sha256": python_hash,
                },
            ]
        },
        "base_runtime_tree": {"files": base_runtime_pyc_files},
    }
    probe_path.write_text(
        "import sys\n"
        "from pathlib import Path\n\n"
        "def configure_no_site_runtime():\n"
        "    prefix = Path(sys.executable).resolve().parents[1]\n"
        "    sys.prefix = str(prefix)\n"
        "    sys.exec_prefix = str(prefix)\n"
        "    purelib = prefix / 'Lib' / 'site-packages'\n"
        "    if str(purelib) not in sys.path:\n"
        "        sys.path.append(str(purelib))\n"
        "    return prefix\n\n"
        "def capture(_scanner_scaffold):\n"
        f"    return {expected_runtime!r}\n",
        encoding="utf-8",
    )
    expected_path = tmp_path / "expected-runtime.json"
    expected_path.write_bytes(launcher._canonical_bytes(expected_runtime))
    expected_sha256 = hashlib.sha256(expected_path.read_bytes()).hexdigest()

    package_root = venv_root / "Lib" / "site-packages" / "k_guard_mcp"
    package_root.mkdir(parents=True)
    startup_marker = tmp_path / "startup-code-executed"
    (package_root.parent / "startup_attack.pth").write_text(
        f"import pathlib; pathlib.Path({str(startup_marker)!r}).write_text('pth')\n",
        encoding="utf-8",
    )
    (package_root.parent / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(startup_marker)!r}).write_text('sitecustomize')\n",
        encoding="utf-8",
    )
    (package_root / "__init__.py").write_text("", encoding="utf-8")
    (package_root / "cli.py").write_text(
        "import ctypes\n"
        "import os\n"
        "import runpy\n"
        "from pathlib import Path\n\n"
        "def main(argv):\n"
        "    workspace = Path(argv[1])\n"
        "    output = Path(argv[argv.index('--json') + 1])\n"
        "    ctypes.WinDLL(os.environ['K_GUARD_NATIVE_CANARY'])\n"
        "    if os.environ.get('K_GUARD_TRANSIENT_MUTATION') == '1':\n"
        "        target = Path(__file__)\n"
        "        backup = target.with_name('_bound_cli.restore')\n"
        "        original = target.read_bytes()\n"
        "        os.replace(target, backup)\n"
        "        target.write_bytes(b'# transient replacement\\n' + original)\n"
        "        target.read_bytes()\n"
        "        target.unlink()\n"
        "        os.replace(backup, target)\n"
        "    if os.environ.get('K_GUARD_NATIVE_METADATA_MUTATION') == '1':\n"
        "        target = Path(os.environ['K_GUARD_NATIVE_CANARY'])\n"
        "        original = target.stat()\n"
        "        os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns + 1000000000))\n"
        "        os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))\n"
        "    if os.environ.get('K_GUARD_SOURCE_MUTATION') == '1':\n"
        "        target = workspace / 'app.py'\n"
        "        original = target.read_bytes()\n"
        "        target.write_bytes(b'# transient source replacement\\n')\n"
        "        target.write_bytes(original)\n"
        "    if os.environ.get('K_GUARD_PREHASH_SOURCE_SWAP') == '1':\n"
        "        target = workspace / 'app.py'\n"
        "        Path(os.environ['K_GUARD_PREHASH_OBSERVED']).write_bytes(target.read_bytes())\n"
        "        target.write_bytes(b\"print('ok')\\n\")\n"
        "    attack = os.environ.get('K_GUARD_EXECUTION_ATTACK', '')\n"
        "    if attack == 'dynamic':\n"
        "        exec(compile('ATTACK = True', '<string>', 'exec'), {})\n"
        "    if attack == 'frozen_spoof':\n"
        "        exec(compile('ATTACK = True', '<frozen runpy>', 'exec'), {})\n"
        "    if attack == 'empty_filename':\n"
        "        exec(compile('ATTACK = True', '', 'exec'), {})\n"
        "    if attack == 'path_spoof':\n"
        "        exec(compile('ATTACK = True', __file__, 'exec'), {})\n"
        "    if attack == 'dataclass_direct':\n"
        "        import dataclasses\n"
        "        dataclasses._create_fn('attack', '', ['return 7'])\n"
        "    if attack == 'function_type':\n"
        "        import types\n"
        "        code = compile('ATTACK = True', '<function-type>', 'exec')\n"
        "        types.FunctionType(code, {})()\n"
        "    if attack == 'marshal_function':\n"
        "        import marshal\n"
        "        import types\n"
        "        blob = marshal.dumps(compile('ATTACK = True', '<marshal-function>', 'exec'))\n"
        "        types.FunctionType(marshal.loads(blob), {})()\n"
        "    if attack == 'code_swap':\n"
        "        def safe_function():\n"
        "            return None\n"
        "        safe_function.__code__ = compile('ATTACK = True', '<code-swap>', 'exec')\n"
        "        safe_function()\n"
        "    if attack == 'outside':\n"
        "        runpy.run_path(str(workspace / 'outside_payload.py'))\n"
        "    if attack == 'process':\n"
        "        marker = os.environ['K_GUARD_CHILD_MARKER']\n"
        "        os.system(f'type nul > \"{marker}\"')\n"
        "    if attack == 'winapi_process':\n"
        "        import _winapi\n"
        "        import subprocess\n"
        "        marker = os.environ['K_GUARD_CHILD_MARKER']\n"
        "        command = f'cmd.exe /c type nul > \"{marker}\"'\n"
        "        startup = subprocess.STARTUPINFO()\n"
            "        _winapi.CreateProcess(None, command, None, None, False, 0, None, None, startup)\n"
            "    if attack == 'relative_native':\n"
            "        ctypes.WinDLL('kernel32.dll')\n"
            "    if attack == 'native_symbol':\n"
            "        ctypes.pythonapi.Py_GetVersion\n"
        "    output.write_text('{}\\n', encoding='utf-8')\n"
        "    return 0\n",
        encoding="utf-8",
    )
    warmup = subprocess.run(
        [
            str(python_path),
            "-I",
            "-B",
            "-S",
            "-c",
            f"import sys; sys.path.append({str(package_root.parent)!r}); import k_guard_mcp.cli",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert warmup.returncode == 0, warmup.stderr
    assert not startup_marker.exists()
    time.sleep(0.1)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_bytes(b"print('ok')\n")
    (workspace / "outside_payload.py").write_bytes(b"VALUE = 1\n")
    expected_source = source_materialization.capture_materialized_tree(workspace)

    def launch(
        name: str,
        *,
        mutate: bool = False,
        metadata_mutate: bool = False,
        source_mutate: bool = False,
        prehash_source_swap: bool = False,
        execution_attack: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        output_path = tmp_path / f"{name}-report.json"
        receipt_path = tmp_path / f"{name}-receipt.json"
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONUSERBASE"}
        }
        if mutate:
            environment["K_GUARD_TRANSIENT_MUTATION"] = "1"
        else:
            environment.pop("K_GUARD_TRANSIENT_MUTATION", None)
        if metadata_mutate:
            environment["K_GUARD_NATIVE_METADATA_MUTATION"] = "1"
        else:
            environment.pop("K_GUARD_NATIVE_METADATA_MUTATION", None)
        environment["K_GUARD_NATIVE_CANARY"] = str(native_canary)
        if source_mutate:
            environment["K_GUARD_SOURCE_MUTATION"] = "1"
        else:
            environment.pop("K_GUARD_SOURCE_MUTATION", None)
        if prehash_source_swap:
            environment["K_GUARD_PREHASH_SOURCE_SWAP"] = "1"
        else:
            environment.pop("K_GUARD_PREHASH_SOURCE_SWAP", None)
        environment["K_GUARD_PREHASH_OBSERVED"] = str(
            tmp_path / f"{name}-prehash-observed"
        )
        environment["K_GUARD_EXECUTION_ATTACK"] = execution_attack or ""
        environment["K_GUARD_CHILD_MARKER"] = str(tmp_path / "child-process-executed")
        completed = subprocess.run(
            [
                str(python_path),
                "-I",
                "-B",
                "-S",
                str(launcher_path),
                "--probe-script",
                str(probe_path),
                "--expected-runtime",
                str(expected_path),
                "--expected-runtime-sha256",
                expected_sha256,
                "--source-probe-script",
                str(source_probe_path),
                "--expected-source-tree-sha256",
                expected_source["tree_sha256"],
                "--expected-source-file-count",
                str(expected_source["file_count"]),
                "--workspace",
                str(workspace),
                "--output",
                str(output_path),
                "--receipt",
                str(receipt_path),
            ],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=LAUNCH_PROCESS_TIMEOUT_SECONDS,
        )
        return completed, json.loads(receipt_path.read_text(encoding="utf-8"))

    stable, stable_receipt = launch("stable")
    assert stable.returncode == 0, (
        stable.stderr
        + "\n"
        + json.dumps(stable_receipt, ensure_ascii=False, sort_keys=True)
    )
    assert stable_receipt["schema"] == launcher.RECEIPT_SCHEMA
    assert stable_receipt["passed"] is True
    assert stable_receipt["runtime_mutation_observed"] is False
    assert stable_receipt["source_mutation_observed"] is False
    assert stable_receipt["pre_source_tree_sha256"] == expected_source["tree_sha256"]
    assert stable_receipt["post_source_tree_sha256"] == expected_source["tree_sha256"]
    assert stable_receipt["source_mutation_monitor"]["passed"] is True
    assert stable_receipt["mutation_event_count"] == 0
    assert stable_receipt["unclassified_notification_count"] == 0
    assert stable_receipt["notification_event_count"] == (
        stable_receipt["accepted_native_load_metadata_event_count"]
        + stable_receipt["accepted_stable_directory_metadata_event_count"]
    )
    assert stable_receipt["runtime_notification_classifier"] == (
        launcher.RUNTIME_NOTIFICATION_CLASSIFIER
    )
    assert stable_receipt["runtime_notification_classifier_errors"] == []
    assert stable_receipt["native_runtime_lock"]["passed"] is True
    assert stable_receipt["native_runtime_lock"]["locked_file_count"] == 1
    assert stable_receipt["runtime_object_attestation"]["passed"] is True
    assert stable_receipt["mutation_monitor_liveness_passed"] is True
    assert stable_receipt["child_process_policy"]["passed"] is True
    assert stable_receipt["child_process_policy"]["final_flags"] & 1 == 1
    assert stable_receipt["child_process_policy"]["prebound_create_process_canary"] == {
        "api": "kernel32.CreateProcessW",
        "blocked": True,
        "winerror": 367,
        "unexpected_process_created": False,
    }
    assert stable_receipt["child_process_policy"]["disable_attempt_canary"] == {
        "blocked": True,
        "winerror": 5,
        "flags_after_attempt": 1,
    }
    assert stable_receipt["child_process_policy"]["prebound_shell_execute_canary"] == {
        "api": "shell32.ShellExecuteW",
        "blocked": True,
        "result": 5,
        "winerror": 367,
    }
    assert stable_receipt["image_load_monitor"]["passed"] is True
    assert stable_receipt["image_load_monitor"]["registered"] is True
    assert stable_receipt["image_load_monitor"]["unregistered"] is True
    assert [row["phase"] for row in stable_receipt["image_load_monitor"]["canaries"]] == [
        "before-scan",
        "after-scan",
    ]
    assert stable_receipt["mutation_guard_canary"] == {
        "before_scan": True,
        "after_scan": True,
        "cleanup_passed": True,
    }
    assert not startup_marker.exists()

    attacked, attacked_receipt = launch("attacked", mutate=True)
    assert attacked.returncode == 86, attacked.stderr
    assert attacked_receipt["passed"] is False
    assert attacked_receipt["runtime_mutation_observed"] is True
    assert attacked_receipt["mutation_event_count"] >= 1
    scanner_monitor = next(
        row for row in attacked_receipt["mutation_monitors"] if row["root"] == "scanner_prefix"
    )
    assert scanner_monitor["event_count"] >= 1
    assert any(row["relative_path"].endswith("cli.py") for row in scanner_monitor["events"])
    assert not (tmp_path / "attacked-report.json").exists()

    metadata_attacked, metadata_attacked_receipt = launch(
        "metadata-attacked",
        metadata_mutate=True,
    )
    assert metadata_attacked.returncode == 86, metadata_attacked.stderr
    assert metadata_attacked_receipt["passed"] is False
    assert metadata_attacked_receipt["runtime_object_attestation"]["passed"] is False
    assert "<prefix>/native-canary.dll" in metadata_attacked_receipt[
        "runtime_object_attestation"
    ]["changed_entries"]
    assert not (tmp_path / "metadata-attacked-report.json").exists()

    source_attacked, source_attacked_receipt = launch(
        "source-attacked",
        source_mutate=True,
    )
    assert source_attacked.returncode == 86, source_attacked.stderr
    assert source_attacked_receipt["passed"] is False
    assert source_attacked_receipt["source_mutation_observed"] is True
    assert source_attacked_receipt["source_mutation_monitor"]["scan_event_count"] >= 1
    assert not (tmp_path / "source-attacked-report.json").exists()

    prehash_attacked, prehash_attacked_receipt = launch(
        "prehash-attacked",
        prehash_source_swap=True,
    )
    assert prehash_attacked.returncode == 86, prehash_attacked.stderr
    assert (tmp_path / "prehash-attacked-prehash-observed").read_bytes() == b"print('swapped')\n"
    assert prehash_attacked_receipt["pre_source_tree_sha256"] == expected_source["tree_sha256"]
    assert prehash_attacked_receipt["post_source_tree_sha256"] == expected_source["tree_sha256"]
    assert prehash_attacked_receipt["source_mutation_observed"] is True
    assert prehash_attacked_receipt["source_mutation_monitor"]["scan_event_count"] >= 1
    assert not (tmp_path / "prehash-attacked-report.json").exists()

    dynamic, dynamic_receipt = launch("dynamic", execution_attack="dynamic")
    assert dynamic.returncode == 86, dynamic.stderr
    assert dynamic_receipt["passed"] is False
    assert dynamic_receipt["execution_audit"]["dynamic_executed_code"]
    assert not (tmp_path / "dynamic-report.json").exists()

    outside, outside_receipt = launch("outside", execution_attack="outside")
    assert outside.returncode == 86, outside.stderr
    assert outside_receipt["passed"] is False
    assert (
        outside_receipt["execution_audit"]["outside_executed_code"]
        or outside_receipt["execution_audit"]["dynamic_executed_code"]
    )
    assert not (tmp_path / "outside-report.json").exists()

    frozen, frozen_receipt = launch("frozen-spoof", execution_attack="frozen_spoof")
    assert frozen.returncode == 86, frozen.stderr
    assert frozen_receipt["passed"] is False
    assert any(
        row["label"] == "<frozen runpy>" and row["allowed"] is False
        for row in frozen_receipt["execution_audit"]["dynamic_exec_events"]
    )

    empty, empty_receipt = launch("empty-filename", execution_attack="empty_filename")
    assert empty.returncode == 86, empty.stderr
    assert empty_receipt["passed"] is False
    assert empty_receipt["execution_audit"]["dynamic_executed_code"]

    spoofed, spoofed_receipt = launch("path-spoof", execution_attack="path_spoof")
    assert spoofed.returncode == 86, spoofed.stderr
    assert spoofed_receipt["passed"] is False
    assert spoofed_receipt["execution_audit"]["dynamic_executed_code"]

    for attack_name in ("function_type", "marshal_function", "code_swap"):
        code_attack, code_attack_receipt = launch(
            attack_name.replace("_", "-"),
            execution_attack=attack_name,
        )
        assert code_attack.returncode == 86, code_attack.stderr
        assert code_attack_receipt["passed"] is False
        assert any(
            row["allowed"] is False
            for row in code_attack_receipt["execution_audit"]["code_object_control_events"]
        )
        assert not (tmp_path / f"{attack_name.replace('_', '-')}-report.json").exists()

    process, process_receipt = launch("process", execution_attack="process")
    assert process.returncode == 86, process.stderr
    assert process_receipt["passed"] is False
    assert process_receipt["execution_audit"]["process_creation_events"]
    assert not (tmp_path / "child-process-executed").exists()

    winapi_process, winapi_process_receipt = launch(
        "winapi-process",
        execution_attack="winapi_process",
    )
    assert winapi_process.returncode == 86, winapi_process.stderr
    assert winapi_process_receipt["passed"] is False
    assert any(
        row["event"] == "_winapi.CreateProcess"
        for row in winapi_process_receipt["execution_audit"]["process_creation_events"]
    )
    assert not (tmp_path / "child-process-executed").exists()

    native, native_receipt = launch("relative-native", execution_attack="relative_native")
    assert native.returncode == 86, native.stderr
    assert native_receipt["passed"] is False
    assert native_receipt["execution_audit"]["outside_executed_code"]

    dataclass_attack, dataclass_receipt = launch(
        "dataclass-direct",
        execution_attack="dataclass_direct",
    )
    assert dataclass_attack.returncode == 86, dataclass_attack.stderr
    assert dataclass_receipt["passed"] is False
    assert dataclass_receipt["execution_audit"]["dynamic_executed_code"]

    native_symbol, native_symbol_receipt = launch(
        "native-symbol",
        execution_attack="native_symbol",
    )
    assert native_symbol.returncode == 86, native_symbol.stderr
    assert native_symbol_receipt["passed"] is False
    assert native_symbol_receipt["execution_audit"]["native_symbol_resolution_events"]
