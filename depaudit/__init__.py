"""depaudit: find supply-chain risks in dependency manifests and lockfiles."""

from __future__ import annotations

__all__ = ["scan", "__version__"]

try:
    from importlib.metadata import version as _version

    __version__ = _version("depaudit")
except Exception:
    __version__ = "0.0.0+dev"


def scan(root: str):
    from depaudit.audit import audit

    return audit(root)
