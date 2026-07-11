# Contributing to SwiftIOC

Thanks for your interest in improving SwiftIOC! This project aims to be a
lightweight, dependable, open-source threat-intelligence collector that anyone
can run locally or in CI. Contributions of all sizes are welcome.

## Getting started

```bash
git clone https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector.git
cd SwiftIOC-Automated-Threat-Intelligence-Collector

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements-dev.txt
```

## Before you open a pull request

Run the same checks CI runs — all four should pass:

```bash
ruff check .                     # lint
pyright                          # static type check
python swiftioc.py --self-test   # built-in sanity assertions
pytest -q                        # offline unit tests
```

The test suite is fully offline: parsers that would hit the network have their
HTTP layer monkeypatched. Please add or update tests when you change behavior —
especially when adding a new feed parser.

## Adding a new feed parser

1. Write a function decorated with `@register_parser("name")` in
   [`swiftioc.py`](swiftioc.py). It receives `(url, ref_url, source, ws)` plus
   any keyword options and returns a `list[Indicator]`.
2. Defang network indicators with `defang_min(...)` and classify values with
   `classify(...)`.
3. Add the source to [`sources.example.yml`](sources.example.yml).
4. Add an **offline** test (monkeypatch `swiftioc.http_get`) covering a small
   representative payload.

## Coding conventions

- Target Python 3.10+.
- Keep the tool dependency-light; justify any new runtime dependency.
- Match the surrounding style; `ruff` and `pyright` configuration lives in
  [`pyproject.toml`](pyproject.toml).

## Security

Please report vulnerabilities privately per [SECURITY.md](SECURITY.md) rather
than opening a public issue.

### Supply-chain note

GitHub Actions in this repo are kept current automatically via
[Dependabot](.github/dependabot.yml). For hardened deployments you may prefer to
pin actions to full commit SHAs (e.g. with
[`pinact`](https://github.com/suzuki-shunsuke/pinact) or
[`ratchet`](https://github.com/sethvargo/ratchet)); Dependabot will continue to
propose SHA bumps once actions are pinned.
