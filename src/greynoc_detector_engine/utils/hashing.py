from __future__ import annotations

import hashlib
import json
from typing import Any


def stable_hash(value: str, length: int = 16) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:length]


def canonical_json_hash(value: Any, length: int = 16) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return stable_hash(canonical, length=length)
