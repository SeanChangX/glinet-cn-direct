# Contributing

Thanks for looking. This project is small, and the bar for changes is set by one
fact: its output decides whether traffic bypasses a VPN.

## Ground rules

**Never edit generated files.** Everything on the `release` branch, and
everything in `dist/`, is machine-written. Fix the generator or the config
instead.

**Never loosen a gate to make a build pass.** If a safety threshold fires, that
is the system working. Find out why before touching `config/policy.toml`, and
explain it in the pull request.

**Keep the generator dependency-free.** It runs on the Python standard library
alone, and that is a security property, not an aesthetic one. `pytest` is the
only development dependency.

## Setup

```bash
python -m venv venv
source venv/Scripts/activate      # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pip install -e .
python -m pytest
```

The test suite runs entirely offline against fixtures in `tests/fixtures/`, so
it is fast and does not depend on upstream availability.

To exercise a real build against live upstream data:

```bash
python -m glinet_rules build --output dist --audit audit
python -m glinet_rules validate dist/cn-ipv4.txt dist/cn-domains.txt dist/cn-direct.txt
bash scripts/acceptance-checks.sh dist
```

## What a good change looks like

| Change | What it needs |
| --- | --- |
| Parser or normalization fix | A test that fails before it and passes after |
| New safety gate | A test proving it blocks the bad case, and one proving it lets the good case through |
| Threshold change in `policy.toml` | The audit report that motivated it, and why the movement is legitimate |
| New or changed upstream source | An entry in `config/expected-sources.json`, a section in `SOURCES.md` saying *why*, and its license in `THIRD_PARTY_NOTICES.md` |
| Adding a bare TLD to `allowed-tld-rules.txt` | An explanation of what else that TLD would route direct. This is a routing-policy change, not a config tweak |
| Adding a never-direct domain | Just open a PR — this list is meant to grow |
| Adding an IP canary | A review date, and a note on why that address is stable |

## Testing expectations

New code needs tests. Specifically:

- **Normalization** must be tested on both the accepted and rejected sides.
  Silently dropping input is a bug; so is silently repairing it.
- **Gates** must be tested for the failure they exist to catch. A gate with no
  failing test is decoration.
- **Determinism** matters: identical input must produce identical bytes.
  `tests/test_build.py` covers this — keep it true.

The end-to-end fixture build in `tests/test_build.py` compares against committed
expected output (`tests/fixtures/expected-*.txt`). If your change alters that
output, update the expected files *in the same commit* and say in the PR why the
new output is correct.

## Reviewing an upstream data change

Upstream data moves daily and most movement is routine. When a scheduled build
fails on a diff gate:

1. Download the run's `rules` artifact and read `audit/report.json`.
2. Look at `audit/ipv4-added.txt` and `audit/ipv4-removed.txt` — is the change
   plausible for a real network reassignment?
3. Check whether the second upstream comparator agrees.
4. If it is legitimate and a threshold is genuinely too tight, change the
   threshold in its own PR with the evidence.
5. If it is not legitimate, leave the gate closed and open an issue upstream.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Commits and branches

`main` is protected: changes arrive by pull request with CI passing. The
`release` branch is bot-managed and must not be edited by hand.

Conventional-ish commit subjects are appreciated (`fix(domains): ...`,
`ci: ...`, `docs: ...`) but not enforced. A clear description of *why* matters
more than the prefix.

Dependabot opens Action and dependency PRs. They are reviewed and merged
manually — an Action update changes code that runs with publishing credentials,
so it is never auto-merged.
