"""Local decision ledger.

The ledger deliberately records metadata only — counts, rule ids, policy
hashes, destination metadata — never plaintext prompts, responses or the
substitution map (paper: "These choices reduce the chance that the
protection system becomes a new sensitive-data repository").
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)

    def record(self, **fields: Any) -> dict[str, Any]:
        entry = {"ts": _now()}
        entry.update(fields)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")
        return entry

    def summary(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"entries": 0, "by_action": {}, "by_rule": {}}
        entries = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        by_action: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for entry in entries:
            action = entry.get("action", "unknown")
            by_action[action] = by_action.get(action, 0) + 1
            for rule_id, count in (entry.get("rule_counts") or {}).items():
                by_rule[rule_id] = by_rule.get(rule_id, 0) + int(count)
        return {"entries": len(entries), "by_action": by_action, "by_rule": by_rule}