"""Policy loading, hashing, and outcome resolution.

The policy file is small and versioned (paper: "versioned policy file").
Every decision cites its policy hash, so a ledger entry can always be
matched to the exact rules that governed it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

VALID_OUTCOMES = ("block", "transform", "release", "review")


class PolicyError(Exception):
    pass


def load_policy(path: Path) -> dict[str, Any]:
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    for required in ("version", "active", "profiles", "destinations"):
        if required not in policy:
            raise PolicyError(f"policy missing required field: {required}")
    if policy["active"] not in policy["profiles"]:
        raise PolicyError(f"active profile '{policy['active']}' is not defined in profiles")
    for name, profile in policy["profiles"].items():
        outcomes = profile.get("outcomes", {})
        for key in ("secrets", "pii", "task_bound_values", "unknown_destination"):
            if key not in outcomes:
                raise PolicyError(f"profile '{name}' missing outcome '{key}'")
            if outcomes[key] not in VALID_OUTCOMES:
                raise PolicyError(f"profile '{name}': outcome '{outcomes[key]}' for '{key}' is not one of {VALID_OUTCOMES}")
        if outcomes["unknown_destination"] not in ("block", "review"):
            raise PolicyError(f"profile '{name}': unknown_destination must be 'block' or 'review'")
    for dest in policy.get("destinations", []):
        for key in ("id", "url", "assurance"):
            if key not in dest:
                raise PolicyError(f"destination missing '{key}': {dest}")
        if not dest["id"] or not dest["url"]:
            raise PolicyError(f"destination id/url must be non-empty: {dest}")
    ids = [d["id"] for d in policy.get("destinations", [])]
    if len(set(ids)) != len(ids):
        raise PolicyError("destination ids must be unique")
    return policy


def policy_hash(policy: dict[str, Any]) -> str:
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def find_destination(policy: dict[str, Any], dest_id: str | None) -> dict[str, Any] | None:
    if not dest_id:
        dest_id = policy.get("default_destination")
    for dest in policy.get("destinations", []):
        if dest["id"] == dest_id:
            return dest
    return None


def validate_upstream_url(url: str) -> str | None:
    """Return a rejection reason, or None if the destination is acceptable."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme == "https":
        return None
    if parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1"):
        return None  # loopback: used by tests and local mock providers
    return f"upstream scheme/host not allowed: {parts.scheme}://{parts.hostname or ''} (policy forwards to https, or to loopback for local testing)"


def outcome_for(profile: dict[str, Any], key: str) -> str:
    outcomes = profile.get("outcomes", {})
    return outcomes.get(key, "block")