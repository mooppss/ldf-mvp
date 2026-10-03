"""Local substitution engine (paper rule 2).

The same value becomes the same placeholder within a request, so the
grammatical role and relationships in the text survive ("Jane Chen" is
[CLIENT_1] in every position). The original-to-substitute mapping stays
on the user's device: by default it lives only in this process's memory
and is never written to disk. Where the optional 'cryptography' package
is installed, the mapping may be persisted encrypted-at-rest
(Fernet over a SHA-256 derived key).

The gateway re-identifies the model's response before returning it to
the local application, so utility is preserved without the original
values ever crossing the provider boundary.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Optional

KIND_LABEL = {
    "api_key_openai": "SECRET",
    "api_key_anthropic": "SECRET",
    "api_key_github": "SECRET",
    "api_key_aws": "SECRET",
    "api_key_google": "SECRET",
    "slack_token": "SECRET",
    "jwt": "TOKEN",
    "bearer_header": "TOKEN",
    "private_key_pem": "KEY_MATERIAL",
    "credential_assignment": "VALUE",
    "email": "EMAIL",
    "phone": "PHONE",
    "card": "CARD",
    "ssn": "SSN",
}


class SubstitutionMap:
    def __init__(self, person_label: str = "CLIENT"):
        self.person_label = person_label
        self._fwd: dict[str, str] = {}   # "kind_key|value" -> placeholder
        self._rev: dict[str, str] = {}   # placeholder -> original
        self._next: dict[str, int] = {}

    @staticmethod
    def kind_key(kind: str) -> str:
        if kind in ("person_name", "known_name"):
            return "person"
        if kind.startswith("api_key") or kind == "slack_token":
            return "secret"
        return kind

    def label_for(self, kind_key: str) -> str:
        if kind_key == "person":
            return self.person_label
        return KIND_LABEL.get(kind_key, kind_key.upper())

    def placeholder_for(self, kind: str, value: str) -> str:
        kk = self.kind_key(kind)
        key = f"{kk}|{value}"
        if key not in self._fwd:
            n = self._next.get(kk, 0) + 1
            self._next[kk] = n
            placeholder = f"[{self.label_for(kk)}_{n}]"
            self._fwd[key] = placeholder
            self._rev[placeholder] = value
        return self._fwd[key]

    def apply(self, text: str, findings) -> str:
        out = text
        for f in sorted(findings, key=lambda f: f.start, reverse=True):
            out = out[:f.start] + self.placeholder_for(f.kind, f.value) + out[f.end:]
        return out

    def reidentify(self, text: str) -> str:
        for placeholder, original in self._rev.items():
            if placeholder in text:
                text = text.replace(placeholder, original)
        return text

    def save_encrypted(self, path, key_material: bytes) -> Optional[str]:
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            return None
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        key = base64.urlsafe_b64encode(hashlib.sha256(key_material).digest())
        payload = json.dumps(
            {"person_label": self.person_label,
             "items": [[k, v] for k, v in self._fwd.items()]},
            ensure_ascii=True)
        Path(path).write_bytes(Fernet(key).encrypt(payload.encode("utf-8")))
        return str(path)

    @classmethod
    def load_encrypted(cls, path, key_material: bytes) -> Optional["SubstitutionMap"]:
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            return None
        key = base64.urlsafe_b64encode(hashlib.sha256(key_material).digest())
        payload = json.loads(Fernet(key).decrypt(Path(path).read_bytes()).decode("utf-8"))
        submap = cls(person_label=payload.get("person_label", "CLIENT"))
        for keyed_value, placeholder in payload["items"]:
            kind_key, value = keyed_value.split("|", 1)
            submap._fwd[keyed_value] = placeholder
            submap._rev[placeholder] = value
            n = int(placeholder.rsplit("_", 1)[1].strip("]"))
            submap._next[kind_key] = max(submap._next.get(kind_key, 0), n)
        return submap