#!/usr/bin/env bash
set -Eeuo pipefail

fail=0

check() {
  local label="$1"
  shift
  printf "%-34s " "${label}"
  if "$@"; then echo "OK"; else echo "FAIL"; fail=1; fi
}

node_engine_ok() { [[ "$(jq -r '.engines.node // empty' package.json)" == "24.x" ]]; }
nvmrc_ok() { [[ "$(tr -d '[:space:]' < .nvmrc)" == "24" ]]; }
devcontainer_node_ok() { [[ "$(jq -r '.features["ghcr.io/devcontainers/features/node:1"].version // empty' .devcontainer/devcontainer.json)" == "24" ]]; }
npm_policy_ok() { grep -Fxq 'engine-strict=true' .npmrc && grep -Fxq 'audit=true' .npmrc && grep -Fxq 'fund=false' .npmrc && grep -Fxq 'save-exact=true' .npmrc; }
lockfile_ok() {
  [[ -s package-lock.json ]] &&
  [[ "$(jq -r '.lockfileVersion // empty' package-lock.json)" == "3" ]] &&
  [[ "$(jq -r '.name // empty' package-lock.json)" == "$(jq -r '.name // empty' package.json)" ]] &&
  [[ "$(jq -r '.version // empty' package-lock.json)" == "$(jq -r '.version // empty' package.json)" ]] &&
  [[ "$(jq -r '.packages[""] .name // empty' package-lock.json)" == "$(jq -r '.name // empty' package.json)" ]]
}

actions_pinned_ok() {
  local workflow=.github/workflows/tooling-smoke.yml
  grep -Eq 'actions/checkout@[0-9a-f]{40}' "${workflow}" && grep -Eq 'actions/setup-node@[0-9a-f]{40}' "${workflow}" && ! grep -Eq 'uses:[[:space:]]+[^[:space:]]+@v[0-9]+' "${workflow}"
}

maltego_ci_ok() {
  local workflow=.github/workflows/tooling-smoke.yml
  grep -Fq 'python3 -m unittest discover -s tests -v' "${workflow}" && grep -Fq 'python3 -m compileall -q maltego' "${workflow}" && grep -Fq "'maltego/install.ps1'" "${workflow}"
}

vercel_bootstrap_ok() {
  local script=scripts/bootstrap-vercel.ps1
  grep -Eq 'RequiredNodeMajor[[:space:]]*=[[:space:]]*24' "${script}" && grep -Eq "PinnedVercelCliVersion[[:space:]]*=[[:space:]]*'58\.4\.4'" "${script}" && ! grep -Fq 'vercel@latest' "${script}"
}

finalizer_ok() {
  local script=scripts/finalize.ps1 workflow=.github/workflows/tooling-smoke.yml
  [[ -s "${script}" ]] && grep -Eq "RequiredBranch[[:space:]]*=[[:space:]]*'main'" "${script}" && grep -Fq "branches/\$RequiredBranch/protection" "${script}" && grep -Fq 'Tooling smoke' "${script}" && grep -Fq 'required_pull_request_reviews' "${script}" && grep -Fq 'required_status_checks' "${script}" && grep -Fq 'enforce_admins' "${script}" && grep -Fq 'allow_force_pushes' "${script}" && grep -Fq 'allow_deletions' "${script}" && grep -Fq 'bootstrap-vercel.ps1' "${script}" && grep -Fq "'scripts/finalize.ps1'" "${workflow}"
}

canonical_env_ok() {
  local expected actual
  expected="$(cat <<'EOF'
PARA11AX_TOKEN=
PARA11AX_USER_SCANNER_URL=
PARA11AX_USER_SCANNER_TOKEN=
ABUSECH_API_KEY=
ABUSEIPDB_API_KEY=
GREYNOISE_API_KEY=
VIRUSTOTAL_API_KEY=
HYBRID_ANALYSIS_API_KEY=
URLSCAN_API_KEY=
WEBAMON_API_KEY=
SENTRY_AUTH_TOKEN=
OTX_API_KEY=
SHODAN_API_KEY=
CENSYS_PAT=
CENSYS_ORG_ID=
PULSEDIVE_API_KEY=
IPINFO_TOKEN=
MALPEDIA_API_TOKEN=
NVD_API_KEY=
VULNCHECK_API_TOKEN=
CLOUDFLARE_RADAR_TOKEN=
RANSOMWARE_LIVE_API_KEY=
MODAT_API_KEY=
EOF
)"
  actual="$(grep -E '^[A-Z0-9_]+=$' .env.example)"
  [[ "${actual}" == "${expected}" ]]
}

bootstrap_secrets_ok() {
  local script=scripts/bootstrap-vercel.ps1 name
  for name in PARA11AX_TOKEN ABUSECH_API_KEY ABUSEIPDB_API_KEY GREYNOISE_API_KEY VIRUSTOTAL_API_KEY HYBRID_ANALYSIS_API_KEY URLSCAN_API_KEY WEBAMON_API_KEY SENTRY_AUTH_TOKEN OTX_API_KEY SHODAN_API_KEY CENSYS_PAT PULSEDIVE_API_KEY IPINFO_TOKEN MALPEDIA_API_TOKEN NVD_API_KEY VULNCHECK_API_TOKEN CLOUDFLARE_RADAR_TOKEN RANSOMWARE_LIVE_API_KEY MODAT_API_KEY; do grep -Fq "'${name}'" "${script}" || return 1; done
  ! grep -Fq 'SECURITYTRAILS_API_KEY' "${script}"
}

docs_runtime_ok() { [[ "$(jq -r '.engines.node // empty' package.json)" == "24.x" ]] && ! grep -Eq 'Node(\.js)?[[:space:]]+22' README.md; }
security_policy_ok() { [[ -s SECURITY.md ]] && grep -Fq 'GitHub Actions must remain pinned to immutable commit SHAs.' SECURITY.md && grep -Fq 'Runtime parity is Node.js 24.x' SECURITY.md && grep -Fq 'read-only' SECURITY.md; }

sensitive_files_untracked() {
  local matches
  matches="$(git ls-files | grep -E '(^|/)\.env($|\.)|\.(pem|key|p12|pfx|jks|keystore)$|(^|/)(samples|captures|artifacts)/' || true)"
  matches="$(printf '%s\n' "${matches}" | grep -v -E '(^|/)\.env\.example$' || true)"
  [[ -z "${matches}" ]]
}

ignore_rules_ok() { grep -Eq '^\.env$' .gitignore && grep -Eq '^\.env\.\*$' .gitignore && grep -Eq '^\*\.pem$' .gitignore && grep -Eq '^samples/$' .gitignore && grep -Eq '^captures/$' .gitignore && grep -Fxq 'maltego/*.mtz' .gitignore; }
no_stale_securitytrails_ok() { ! grep -Fq 'SECURITYTRAILS_API_KEY' .env.example scripts/bootstrap-vercel.ps1 README.md; }

qa_suite_ok() {
  [[ -s test/fuzz-deterministic.test.js ]] && [[ -s test/chaos-provider.test.js ]] && [[ -s test/manifest-invariants.test.js ]] && grep -Fq "1000 deterministic arbitrary strings" test/fuzz-deterministic.test.js && grep -Fq 'transient provider failures are never negative-cached' test/chaos-provider.test.js && grep -Fq 'every active workflow adapter is registered' test/manifest-invariants.test.js
}

vnext_api_surface_ok() { local path; for path in api/para11ax/enrich.js api/para11ax/batch.js api/para11ax/stix.js api/para11ax/meta.js api/para11ax/status.js api/para11ax/health.js 'api/para11ax/[...path].js'; do [[ -s "${path}" ]] || return 1; done; }
egress_boundary_ok() { grep -Fq 'safeFetch' src/core/provider-runner.js && ! grep -R -E '[^[:alnum:]_]fetch[[:space:]]*\(' src/providers --include='*.js'; }

release_docs_ok() {
  local path
  for path in docs/ARCHITECTURE.md docs/EVIDENCE-SCHEMA.md docs/PROVIDERS.md docs/API.md docs/THREAT-MODEL.md docs/OPERATIONS.md release-manifest.json scripts/generate-release-manifest.mjs; do [[ -s "${path}" ]] || return 1; done
  for path in ARCHITECTURE EVIDENCE-SCHEMA PROVIDERS API THREAT-MODEL OPERATIONS; do grep -Fq "docs/${path}.md" README.md || return 1; done
  grep -Fq 'release-manifest.json' README.md
}

release_manifest_ok() { node scripts/generate-release-manifest.mjs --check; }

echo "== Repository invariants =="
check "package.json Node 24.x" node_engine_ok
check ".nvmrc Node 24" nvmrc_ok
check "devcontainer Node 24" devcontainer_node_ok
check "npm strict/deterministic policy" npm_policy_ok
check "npm lockfile committed" lockfile_ok
check "GitHub Actions SHA-pinned" actions_pinned_ok
check "Maltego CI gates present" maltego_ci_ok
check "Vercel bootstrap pinned" vercel_bootstrap_ok
check "GitHub/Vercel finalizer" finalizer_ok
check "canonical environment template" canonical_env_ok
check "bootstrap secret set canonical" bootstrap_secrets_ok
check "README runtime parity" docs_runtime_ok
check "security policy present" security_policy_ok
check "sensitive artifacts untracked" sensitive_files_untracked
check "secret/artifact ignore rules" ignore_rules_ok
check "SecurityTrails stale config absent" no_stale_securitytrails_ok
check "vNext adversarial QA suite" qa_suite_ok
check "vNext API surface present" vnext_api_surface_ok
check "central egress boundary" egress_boundary_ok
check "release docs linked" release_docs_ok
check "release manifest current" release_manifest_ok

echo
echo "== Dependency audit =="
npm audit --omit=dev

if ((fail != 0)); then echo "[!] Repository invariant verification failed." >&2; exit 2; fi
echo "[+] Repository invariant verification passed."
