# Contributing to AgentPay SDK

Thanks for contributing. This guide follows common practices used by mature open-source projects (clear scope, reproducible reports, and review-ready pull requests).

## Scope

Contributions are welcome for:

- bug fixes
- tests and reliability improvements
- documentation
- developer experience and tooling
- security hardening (non-sensitive issues only; see [SECURITY.md](SECURITY.md) for vulnerabilities)

## Before you start

1. Check existing issues and pull requests to avoid duplicates.
2. Open an issue for non-trivial changes before implementation.
3. Keep pull requests focused. One logical change per PR.

## What to submit

### Bug report

Submit an issue with:

- clear title and expected vs actual behavior
- reproducible steps
- environment details (OS, Node version, Rust version, CLI version/commit)
- logs or screenshots (with secrets redacted)
- minimal reproduction when possible

### Feature request

Submit an issue with:

- problem statement (what is hard today)
- proposed solution
- alternatives considered
- breaking-change risk
- security implications

### Pull request

Submit a PR that includes:

- a short problem statement
- a summary of code changes
- tests for changed behavior (or clear justification if not possible)
- updated docs/CLI help for user-facing changes
- migration notes for breaking changes

## Development setup

```bash
pnpm install
npm run build
npm run test
npm run lint
npm run typecheck
```

Rust workspace checks (recommended when touching `crates/*`):

```bash
cargo test --workspace
```

## Pull request quality bar

- no unrelated refactors
- no plaintext secrets or private keys in code, tests, fixtures, logs, or screenshots
- no force-pushes after review comments without addressing discussion context
- all relevant checks pass locally

## Commit guidance

- Use clear commit messages that describe intent.
- Reference issue IDs when relevant.
- Squash noisy WIP commits before merge.

## Security issues

Do not file public issues for exploitable vulnerabilities. Use the private process in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the repository [MIT License](LICENSE).
