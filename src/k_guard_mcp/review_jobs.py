from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Callable
from uuid import uuid4

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme


class ReviewQueueFull(RuntimeError):
    pass


@dataclass
class _ReviewJob:
    review_id: str
    kind: str
    dedupe_key: str
    submitted_at: str
    future: Future[dict]
    completed_at: str = ""


class ReviewJobRegistry:
    """Bounded in-process jobs for MCP clients with short tool-call timeouts."""

    def __init__(self, *, max_jobs: int = 8, max_workers: int = 1) -> None:
        if max_jobs <= 0 or max_workers <= 0:
            raise ValueError("Review job limits must be positive.")
        self.max_jobs = max_jobs
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="k-guard-review")
        self._jobs: dict[str, _ReviewJob] = {}
        self._lock = RLock()

    def submit(self, *, kind: str, dedupe_key: str, work: Callable[[], dict]) -> tuple[str, bool]:
        with self._lock:
            for job in self._jobs.values():
                if job.kind == kind and job.dedupe_key == dedupe_key and not job.future.done():
                    return job.review_id, True
            self._evict_completed_locked()
            if len(self._jobs) >= self.max_jobs:
                raise ReviewQueueFull("All review job slots are active.")
            review_id = str(uuid4())
            future = self._executor.submit(work)
            job = _ReviewJob(
                review_id=review_id,
                kind=kind,
                dedupe_key=dedupe_key,
                submitted_at=_now(),
                future=future,
            )
            self._jobs[review_id] = job
            future.add_done_callback(lambda _future, job_id=review_id: self._mark_completed(job_id))
            return review_id, False

    def inspect(self, review_id: str, *, wait_seconds: float = 0.0) -> dict:
        with self._lock:
            job = self._jobs.get(review_id)
        if job is None:
            return {"state": "not_found", "review_id": review_id, "raw_returned": False}

        if not job.future.done() and wait_seconds > 0:
            try:
                job.future.result(timeout=wait_seconds)
            except TimeoutError:
                pass
            except Exception:
                pass

        state = "completed" if job.future.done() else ("running" if job.future.running() else "queued")
        base = {
            "state": state,
            "review_id": review_id,
            "kind": job.kind,
            "submitted_at": job.submitted_at,
            "completed_at": job.completed_at or None,
            "raw_returned": False,
        }
        if state != "completed":
            return base
        try:
            result = job.future.result()
        except Exception as exc:
            return {
                **base,
                "state": "failed",
                "error_type": type(exc).__name__,
                "error_ref": evidence_hash(str(exc)),
                "hash_scheme": evidence_hash_scheme(),
            }
        if not isinstance(result, dict):
            return {
                **base,
                "state": "failed",
                "error_type": "InvalidReviewResult",
                "error_ref": evidence_hash(type(result).__name__),
                "hash_scheme": evidence_hash_scheme(),
            }
        return {**base, "result": deepcopy(result)}

    def shutdown(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=not wait)

    def _mark_completed(self, review_id: str) -> None:
        with self._lock:
            job = self._jobs.get(review_id)
            if job is not None and not job.completed_at:
                job.completed_at = _now()

    def _evict_completed_locked(self) -> None:
        while len(self._jobs) >= self.max_jobs:
            completed = next((job_id for job_id, job in self._jobs.items() if job.future.done()), None)
            if completed is None:
                return
            self._jobs.pop(completed, None)


def _now() -> str:
    return datetime.now(UTC).isoformat()
