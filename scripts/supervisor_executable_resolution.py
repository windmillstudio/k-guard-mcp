from __future__ import annotations

import shutil
from pathlib import Path
from typing import Mapping


def _native_npm_shim_candidate(provider: str | None, executable: Path) -> Path | None:
    if executable.suffix.lower() != ".cmd":
        return None
    npm_root = executable.parent
    if provider == "claude" and executable.stem.lower() == "claude":
        candidate = npm_root / "node_modules" / "@anthropic-ai" / "claude-code" / "bin" / "claude.exe"
        return candidate if candidate.is_file() and not candidate.is_symlink() else None
    if provider == "glm" and executable.stem.lower() == "cline":
        candidates = sorted(
            (npm_root / "node_modules" / "cline" / "node_modules" / "@cline").glob(
                "cli-windows-*/bin/cline.exe"
            )
        )
        valid = [candidate for candidate in candidates if candidate.is_file() and not candidate.is_symlink()]
        return valid[0] if len(valid) == 1 else None
    return None


def resolve_supervisor_executable(executable: str, *, provider: str | None = None) -> str:
    """Return an executable path that subprocess can invoke on Windows too."""
    if not isinstance(executable, str) or not executable.strip():
        raise ValueError("supervisor executable is required")
    resolved = shutil.which(executable)
    if resolved:
        candidate = Path(resolved).resolve(strict=False)
    else:
        candidate = Path(executable).expanduser()
        if not candidate.is_file():
            return executable
        candidate = candidate.resolve(strict=False)
    native = _native_npm_shim_candidate(provider, candidate)
    if native is not None:
        return str(native.resolve(strict=False))
    return str(candidate)


def resolve_supervisor_executables(executables: Mapping[str, str]) -> dict[str, str]:
    return {
        provider: resolve_supervisor_executable(executable, provider=provider)
        for provider, executable in executables.items()
    }
