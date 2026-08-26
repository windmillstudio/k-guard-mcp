from __future__ import annotations

import itertools


class IdFactory:
    def __init__(self, prefix: str = "finding") -> None:
        self.prefix = prefix
        self._counter = itertools.count(1)

    def next(self) -> str:
        return f"{self.prefix}-{next(self._counter):04d}"

