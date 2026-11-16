# gha-audit

GitHub Actions workflows run with your secrets and your repository token, and most breaches through CI come from a handful of well-known mistakes. gha-audit reads `.github/workflows` and finds them, with a fix for each.

**Live demo:** https://jvch0512.github.io/gha-audit/ (a report on the synthetic workflows in `examples/`)

Ruby 3.x, standard library only, offline.

## Use

```bash
ruby bin/gha-audit .github/workflows
ruby bin/gha-audit .github/workflows --json
ruby bin/gha-audit .github/workflows --html > report.html
ruby bin/gha-audit .github/workflows --fail-on high     # exit 1 in CI
```

See [examples/workflows](examples/workflows) (three vulnerable, one clean) and [docs/sample-output.txt](docs/sample-output.txt).

## Rules

| Rule | Severity | What it catches |
|---|---|---|
| GHA001 | critical | `pull_request_target` that checks out the pull request head: attacker code runs with secrets |
| GHA002 | high | attacker-controlled values (`issue.title`, `pull_request.head.ref`, `comment.body`, commit messages...) expanded inline in a `run:` script |
| GHA003 | medium | third-party actions and reusable workflows not pinned to a full commit SHA |
| GHA004 | medium | no `permissions:` block, or `write-all` |
| GHA005 | high | `curl ... \| bash` |
| GHA006 | high | self-hosted runners reachable from pull requests |
| GHA007 | high | `ACTIONS_ALLOW_UNSECURE_COMMANDS` |
| GHA008 | medium | `secrets: inherit` into reusable workflows |

## Limits

- Static and syntactic: it reads the YAML, it does not resolve reusable workflows or composite actions, and it does not know your repository settings (fork approval, environment protection, default token permissions).
- Official `actions/*` and `github/*` actions at a tag are not flagged for pinning, a deliberate trade-off. Pin everything if your policy requires it.
- Expression analysis is pattern based and may miss indirect flows (a step output that carries an untrusted value).

## Where it fits

Pre-merge CI gate, supply-chain reviews, vendor and M&A due diligence, and a fixed-price "CI/CD security review" service for engineering teams.

## Tests

```bash
ruby test/gha_audit_test.rb   # 12 tests, 42 assertions
```

MIT.

## Validated on real data

This tool was run on public corpora and the false positives it produced were fixed. Corpus, counts and bugs found are in [docs/validation.md](docs/validation.md).
