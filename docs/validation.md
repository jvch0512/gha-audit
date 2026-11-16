# Validation on real data

Counts below were produced by running the tool on public data, not on the synthetic samples in `examples/`.

## Corpus
actions/starter-workflows at commit `e3c451d`: 172 workflow files in `ci`, `deployments`, `automation` and `code-scanning`.

## Result
120 findings: 71 GHA003 (medium), 47 GHA004 (medium) and 2 GHA005 (high). Every GHA004 (an action referenced by tag instead of a commit SHA) was checked and is correct.

## Own repositories
The tool was run over the workflows of all 119 repositories of this portfolio. It found 62 workflows without a `permissions:` block and unpinned actions. All were fixed (least-privilege `contents: read`, actions pinned to SHAs), and a second run reports zero findings.
