# Contributing to sentinel-inject

Thanks for helping improve sentinel-inject.

## Development setup

### Python

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
cd python
pip install -e ".[dev]"
```

3. Run tests:

```bash
pytest
```

### TypeScript

1. Install dependencies:

```bash
cd typescript
npm install
```

2. Build and test:

```bash
npm run build
npm test -- --passWithNoTests
```

## Pull request guidelines

- Keep changes focused and scoped.
- Add or update tests for behavior changes.
- Update documentation when APIs or behavior change.
- Ensure CI passes before requesting review.

## Reporting security issues

Do not open public issues for vulnerabilities. Follow `SECURITY.md` for responsible disclosure.
