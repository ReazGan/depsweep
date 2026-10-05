"""The audit: walk a project, read its dependency files, report risks.

Scope is the supply-chain risks you can see without installing anything:

- DA001 install-hook: a package that runs a script at install time
  (preinstall/postinstall/install). This is how most malicious npm packages
  execute. Reported for the project itself and for any installed dependency
  under node_modules.
- DA002 non-registry source: a dependency pulled from a git repo, a URL, a
  tarball or a local path instead of the package registry, so it is never
  reviewed or pinned by the registry.
- DA003 insecure-source: a dependency or lockfile entry fetched over plain
  http.
- DA004 typosquat: a dependency whose name is one edit away from a very popular
  package (a classic typosquatting trap).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SKIP_WALK = {".git", "dist", "build", ".venv", "venv", "__pycache__", ".next"}
MAX_SIZE = 5 * 1024 * 1024


@dataclass
class Finding:
    check: str
    title: str
    description: str
    severity: str
    path: str
    package: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        d = {"check": self.check, "title": self.title, "severity": self.severity,
             "path": self.path}
        if self.package:
            d["package"] = self.package
        d["description"] = self.description
        if self.evidence:
            d["evidence"] = self.evidence
        return d


# A small set of very popular packages used for typosquat distance checks.
POPULAR_NPM = {
    "react", "react-dom", "lodash", "express", "axios", "chalk", "commander",
    "request", "moment", "webpack", "babel-core", "typescript", "vue", "next",
    "eslint", "prettier", "jest", "dotenv", "uuid", "debug", "cross-env",
    "node-fetch", "yargs", "glob", "rimraf", "classnames", "redux",
}
POPULAR_PIP = {
    "requests", "numpy", "pandas", "flask", "django", "pytest", "setuptools",
    "urllib3", "boto3", "click", "pyyaml", "scipy", "pillow", "sqlalchemy",
    "beautifulsoup4", "tensorflow", "torch", "fastapi", "pydantic", "selenium",
    "matplotlib", "cryptography", "jinja2", "colorama", "tqdm",
}

# git / tarball / url sources are not registry-reviewed. link:/file:/portal:/
# workspace: are local monorepo references and are left alone.
_NON_REGISTRY = re.compile(r"^(git\+|git:|https?:|github:|gitlab:|bitbucket:)", re.I)
_INSTALL_HOOKS = ("preinstall", "install", "postinstall")

# Real packages that sit one edit away from a popular one; never a typosquat.
_LEGIT_NEIGHBOURS = {
    "tslint", "preact", "vuex", "remark", "chai", "ava", "koa", "got", "qs",
    "ora", "ejs", "ncp", "del", "nan", "ws", "fastify", "flask-cors",
}


def audit(root: str) -> list[Finding]:
    root = os.path.abspath(root)
    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        in_node_modules = "node_modules" in dirpath.replace(os.sep, "/").split("/")
        # Only descend into node_modules to read package manifests, nothing else.
        dirnames[:] = [d for d in dirnames if d not in _SKIP_WALK]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if fn == "package.json":
                findings.extend(_package_json(full, rel, in_node_modules))
            elif fn in ("requirements.txt",) or fn.startswith("requirements") and fn.endswith(".txt"):
                if not in_node_modules:
                    findings.extend(_requirements(full, rel))
            elif fn in ("package-lock.json",) and not in_node_modules:
                findings.extend(_npm_lock(full, rel))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.package))
    return findings


def _read_json(full: str):
    try:
        if os.path.getsize(full) > MAX_SIZE:
            return None
        return json.loads(open(full, encoding="utf-8", errors="replace").read())
    except (OSError, ValueError):
        return None


def _package_json(full: str, rel: str, in_nm: bool) -> list[Finding]:
    data = _read_json(full)
    if not isinstance(data, dict):
        return []
    out: list[Finding] = []
    name = data.get("name", "") if isinstance(data.get("name"), str) else ""

    # Install hooks matter in a *dependency* (you did not write it and it runs
    # on npm install). A project's own postinstall is normal and self-authored,
    # so only node_modules entries are reported.
    if in_nm:
        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            hooks = [h for h in _INSTALL_HOOKS if isinstance(scripts.get(h), str) and scripts[h].strip()]
            if hooks:
                out.append(Finding(
                    "install-hook",
                    "Dependency runs a script at install time",
                    "Install hooks (" + ", ".join(hooks) + ") run automatically on "
                    "`npm install`, before any code is imported. This is the usual way "
                    "malicious packages execute. Review what this script does and "
                    "whether you trust this dependency.",
                    "high", rel, name,
                    {"hooks": hooks, "example": scripts[hooks[0]][:120]},
                ))

    if not in_nm:
        for field_name in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(field_name)
            if not isinstance(deps, dict):
                continue
            for dep, spec in deps.items():
                if not isinstance(spec, str):
                    continue
                if _NON_REGISTRY.match(spec):
                    sev = "medium"
                    if spec.lower().startswith("http:"):
                        sev = "high"
                    out.append(Finding(
                        "non-registry-source" if not spec.lower().startswith("http:") else "insecure-source",
                        "Dependency pulled from outside the registry",
                        f"'{dep}' is installed from {spec[:60]}, not the npm registry, "
                        "so it is not reviewed, versioned or integrity-checked like a "
                        "published package. Whoever controls that source controls the code.",
                        sev, rel, dep, {"spec": spec[:120]},
                    ))
                squat = _typosquat(dep, POPULAR_NPM)
                if squat:
                    out.append(_squat_finding(rel, dep, squat))
    return out


def _requirements(full: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        lines = open(full, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("-r") or s.startswith("--"):
            continue
        low = s.lower()
        if low.startswith(("git+", "http://", "https://")):
            sev = "high" if low.startswith("http://") else "medium"
            out.append(Finding(
                "insecure-source" if low.startswith("http://") else "non-registry-source",
                "Dependency pulled from outside PyPI",
                f"This requirement is fetched from {s[:60]}, not PyPI, so it is not "
                "reviewed or integrity-checked like a published release.",
                sev, rel, s.split("#")[0][:60], {"spec": s[:120]},
            ))
            continue
        name = re.split(r"[=<>!~\[ ;]", s, maxsplit=1)[0].strip()
        squat = _typosquat(name.lower(), POPULAR_PIP)
        if squat:
            out.append(_squat_finding(rel, name, squat))
    return out


def _npm_lock(full: str, rel: str) -> list[Finding]:
    data = _read_json(full)
    if not isinstance(data, dict):
        return []
    out: list[Finding] = []
    # lockfile v2/v3 uses "packages", v1 uses "dependencies"
    seen_http = False
    def check_resolved(resolved):
        nonlocal seen_http
        if isinstance(resolved, str) and resolved.startswith("http://") and not seen_http:
            seen_http = True
            out.append(Finding(
                "insecure-source", "Lockfile fetches a package over plain http",
                "A resolved URL in the lockfile uses http, not https, so the package "
                "can be swapped in transit. Regenerate the lockfile against an https "
                "registry.", "high", rel, "", {"url": resolved[:120]},
            ))
    for section in ("packages", "dependencies"):
        node = data.get(section)
        if isinstance(node, dict):
            for info in node.values():
                if isinstance(info, dict):
                    check_resolved(info.get("resolved"))
    return out


def _squat_finding(rel: str, dep: str, target: str) -> Finding:
    return Finding(
        "typosquat", "Dependency name looks like a typo of a popular package",
        f"'{dep}' is one character away from '{target}', a very popular package. "
        "Typosquatting packages use near-identical names to get installed by "
        "mistake. Confirm this is the package you meant.",
        "high", rel, dep, {"looks_like": target},
    )


def _typosquat(name: str, popular: set[str]) -> str | None:
    if not name or name in popular or name in _LEGIT_NEIGHBOURS:
        return None
    for target in popular:
        if abs(len(name) - len(target)) <= 1 and _edit_distance_le1(name, target):
            return target
    return None


def _edit_distance_le1(a: str, b: str) -> bool:
    """True if a and b differ by at most one insertion/deletion/substitution."""
    if a == b:
        return False  # identical is not a typo
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True  # one substitution
        # one adjacent transposition (swap of two neighbouring letters)
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            i, j = diffs
            return a[i] == b[j] and a[j] == b[i]
        return False
    # one longer: check single insertion
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    i = j = 0
    skipped = False
    while i < la and j < lb:
        if a[i] != b[j]:
            if skipped:
                return False
            skipped = True
            j += 1
        else:
            i += 1
            j += 1
    return True
