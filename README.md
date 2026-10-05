# depsweep

[![CI](https://github.com/ReazGan/depsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/ReazGan/depsweep/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/depsweep)](https://pypi.org/project/depsweep/)

Find supply-chain risks in your npm and pip dependency files.

Most malicious packages don't need you to call them. They run a script the
moment you `npm install`, or they ride in on a name one letter off a package you
trust. depsweep reads `package.json`, `requirements.txt`, lockfiles and installed
`node_modules` manifests and flags the risks you can see without running anything.

Runs offline. No registry calls, nothing leaves your machine.

![depsweep flagging an install hook in a dependency, a git source and a typosquat](https://raw.githubusercontent.com/ReazGan/depsweep/main/docs/screenshot.svg)

## Install

```
pip install depsweep
```

## Usage

```
depsweep                 scan the current directory
depsweep path            scan a directory
depsweep --min high      only high and critical findings
depsweep --json          machine-readable output
```

Exit status is `0` when clean, `1` when there is a finding at or above the fail
level (`--fail-on`, default `high`), and `2` on error.

### pre-commit

```yaml
repos:
  - repo: https://github.com/ReazGan/depsweep
    rev: v0.1.0
    hooks:
      - id: depsweep
```

### GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: ReazGan/depsweep@v0.1.0
```

## What it checks

| Check | Severity | What it finds |
|-------|----------|---------------|
| `install-hook` | high | A dependency under `node_modules` that runs a script on install (`preinstall`/`install`/`postinstall`). The usual malware entry point. |
| `typosquat` | high | A dependency whose name is one edit (incl. a letter swap) from a very popular package. |
| `insecure-source` | high | A dependency or lockfile entry fetched over plain `http`. |
| `non-registry-source` | medium | A dependency pulled from a git repo or URL instead of the registry. |

A project's own `postinstall` is not flagged (you wrote it); only dependencies
are. Known real packages that happen to sit next to a popular name (`tslint`,
`preact`, ...) are not reported as typosquats.

Run it after `npm install` to see dependency install hooks; run it on the repo
alone to check manifests and lockfiles.

## License

MIT
