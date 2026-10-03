"""Local Disclosure Firewall (LDF) — MVP.

A user-controlled gateway for prompts and text documents: applications
send requests to the gateway instead of directly to a cloud model. The
gateway makes a disclosure decision locally, applies the user's policy,
and records what happened — per the accompanying policy paper.

Five rules (paper §"Put a disclosure decision at the edge"):
  1. Credentials and secrets are blocked        -> ldf.detectors + gateway
  2. Identity not necessary is transformed      -> ldf.transform
  3. Task-required exact values are an explicit decision -> policy profiles
     (X-LDF-Exact: task-required -> task_bound_values outcome)
  4. Unknown provider behavior is a risk signal -> destination allowlist
  5. The provider boundary includes the client  -> egress review (see README
     for the OS-level companion this MVP points to)
"""

__version__ = "0.1.1"