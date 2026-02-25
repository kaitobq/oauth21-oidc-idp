.PHONY: bootstrap harness-smoke check

bootstrap:
	chmod +x scripts/harness_smoke.sh
	@echo "bootstrap complete"

harness-smoke:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_smoke.sh

check: bootstrap harness-smoke
