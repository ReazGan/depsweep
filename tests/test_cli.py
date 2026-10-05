from __future__ import annotations

import json

from click.testing import CliRunner

from depaudit.cli import main


def _w(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_clean_exit_zero(tmp_path):
    _w(tmp_path, "package.json", json.dumps({"name": "a", "dependencies": {"react": "^18.0.0"}}))
    res = CliRunner().invoke(main, [str(tmp_path), "--no-color"])
    assert res.exit_code == 0 and "clean" in res.output


def test_findings_exit_one(tmp_path):
    _w(tmp_path, "package.json", json.dumps({"name": "a", "dependencies": {"recat": "^1.0.0"}}))
    res = CliRunner().invoke(main, [str(tmp_path), "--no-color"])
    assert res.exit_code == 1 and "typosquat" in res.output


def test_json(tmp_path):
    _w(tmp_path, "node_modules/evil/package.json", json.dumps({"name": "evil", "scripts": {"postinstall": "x"}}))
    res = CliRunner().invoke(main, [str(tmp_path), "--json"])
    data = json.loads(res.output)
    assert any(f["check"] == "install-hook" for f in data["findings"])


def test_fail_on(tmp_path):
    # a git source is medium; high findings fail by default
    _w(tmp_path, "package.json", json.dumps({"name": "a", "dependencies": {"x": "git+https://h/x"}}))
    assert CliRunner().invoke(main, [str(tmp_path)]).exit_code == 0
    assert CliRunner().invoke(main, [str(tmp_path), "--fail-on", "medium"]).exit_code == 1
