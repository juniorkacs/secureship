#!/usr/bin/env bash
# Run the pipeline's code-level gates locally, in the same order as CI.
# Container build, Trivy, Syft and gitleaks run in GitHub Actions (or install them locally).
set -euo pipefail
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }

step "Install (exact versions from package-lock.json)"
npm ci --no-audit --no-fund

step "Lint"
npm run lint

step "Type check"
npm run typecheck

step "Unit and API tests with coverage thresholds"
npm run test:ci

step "Dependency audit (production, high and critical)"
npm run audit:deps

if command -v semgrep >/dev/null; then
  step "Semgrep (project rules)"
  semgrep scan --config .semgrep/project-rules.yml --metrics=off --error
else
  echo "semgrep not installed; skipping (pip install semgrep)"
fi

step "Build"
npm run build

for tool in gitleaks trivy syft; do
  command -v "$tool" >/dev/null || echo "$tool not installed; CI runs it."
done
printf '\n\033[1;32mAll local gates passed.\033[0m\n'
