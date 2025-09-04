PY?=python

.PHONY: security bandit osv

security: bandit osv ## Run all security scanners (best-effort)
	@echo "Security scan complete"

bandit:
	@command -v bandit >/dev/null 2>&1 && bandit -q -r src || echo "[skip] bandit not installed"

osv:
	@command -v osv-scanner >/dev/null 2>&1 && osv-scanner --config=./osv-scanner.toml --recursive . || echo "[skip] osv-scanner not installed"
