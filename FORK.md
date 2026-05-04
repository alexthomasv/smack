# SMACK Fork Notes

This repository is maintained as a Swoosh-oriented fork of upstream SMACK.
The upstream project lives at https://github.com/smackers/smack.

## Branches

- `main` is the canonical fork integration branch.
- `upstream/main` should track official SMACK.
- `main-swoosh` may be kept as a compatibility alias for older Swoosh tooling,
  but new work should target `main`.

## Rebase Policy

Before rebasing or rewriting fork history, create backup refs for the current
fork branches. Rebase the fork stack onto `upstream/main`, keep commits topical,
and push rewritten branches with `--force-with-lease`.

Fork-specific changes should stay clearly separated from upstream SMACK updates:
avoid committing debug output, WIP commit messages, or unrelated formatting churn.
