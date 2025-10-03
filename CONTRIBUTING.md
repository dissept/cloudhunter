# Contributing to Cloudhunter

Thanks for considering a contribution!

## Quick Start
1. Fork the repo and create a feature branch.
2. Set up dev env: `make dev` (or see README in each component).
3. Write tests. Run `make test`.
4. Submit a PR with a clear description and screenshots/logs where helpful.

## Coding Standards
- Python: `ruff` + `black`, type hints with `mypy` where possible.
- Commit messages: Conventional Commits (`feat:`, `fix:`, `docs:`...).

## Security
Never commit secrets. Use `.env` and your cloud provider’s secret manager or Vault.
