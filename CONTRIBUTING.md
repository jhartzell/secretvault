# Contributing

Thanks for your interest in contributing.

## How to report bugs

Use the bug report template at `.github/ISSUE_TEMPLATE/bug_report.md`.

## How to suggest features

Use the feature request template at `.github/ISSUE_TEMPLATE/feature_request.md`.

## Dev environment setup

1. Fork and clone the repository.
2. Install dependencies.
3. Run the project locally.

```bash
go mod download
task dev
```

## How to run tests

```bash
task test
```

## PR process and expectations

- Keep pull requests focused and small.
- Link related issue(s).
- Update docs/tests when behavior changes.
- Expect review before merge.

## Types of contributions wanted

- Bug fixes
- Documentation improvements
- Test coverage improvements
- Small, focused enhancements

## Code style / linting requirements

Run linting/formatting before opening a PR.

```bash
golangci-lint run
```

## Response time expectations

- Issues and PRs: target first maintainer response within 48 hours.
