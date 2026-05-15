# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0]

### Breaking changes

- **Requires CVE-PaaS exposing the `/v1/` API.** dtrg now calls `POST /v1/cve` (batch) and `GET /v1/get_info/<id>` is no longer used. Operators running an older CVE-PaaS need to upgrade.

### Added

- `summary.json` bundled in every report ZIP next to `result.docx` / `result.xlsx`. Carries the project metadata and the vulnerable-components list in a JSON-serializable shape (versioned via `schemaVersion: 1`) so CI pipelines can do severity gates, dashboards or diffing without parsing Office files.
- Docker images now publish for `linux/amd64` **and** `linux/arm64`. Apple Silicon dev machines and arm SBCs (Raspberry Pi, Ampere) get a native image instead of QEMU emulation.
- **Diff between project versions.** New endpoints `POST /reports/diff` (form) and `POST /api/v1/reports/diff` (JSON, CSRF-exempt, gated by `DTRG_API_KEY`). Takes two DT project UUIDs; returns a ZIP with `result.xlsx` (six sheets including side-by-side project metadata, a unioned `Vulnerable dependencies` with `Used version (A) / (B)`, three issue sheets `Added` / `Removed` / `Common`, and a Technical sheet feeding the diagram) plus `summary.json` (`kind: "diff"`) describing what was added, removed and stayed common between the two snapshots. The xlsx is rendered into the `reports/draft_diff.xlsx` template. The pair is auto-swapped so the project with the more recent `lastBomImport` always ends up as B, regardless of the order the operator picked.
- The browser form gains a "Compare with another version" checkbox. When checked, a second project select appears (lazy-loaded, debounced search, paginated — same UX as the main one) and the form's submit posts to `/reports/diff` instead of `/reports/get_report`.
- **CVE-PaaS batch fetch.** dtrg now collects every canonical CVE id from the SBOM and asks CVE-PaaS for them in a single `POST /v1/cve` call (chunked into batches of 50). Replaces the per-CVE round-trip and slashes report time on large projects.
- **Wider CVE-PaaS enrichment.** CVSS score, EPSS score and the `is_kev` / `is_poc` / `is_nuclei_template` flags from CVE-PaaS now reach each vulnerability. The `Additional info` column in the Excel report carries `KEV: <url>` / `POC: <url>` / `Nuclei: <url>` lines for any priority that has them; `summary.json` exposes `cvss`, `epss`, `isKev`, `isPoc`, `isNucleiTemplate` per vulnerability and inside diff entries.
- **Rate limit on `/api/v1/*`.** Flask-Limiter caps requests per client IP. Default `60/minute`, configurable via the new `DTRG_API_RATE_LIMIT` env (empty disables). 429 responses are JSON for `/api/v1/*` callers; the form routes and `/health` stay unlimited.
- **SSRF allowlist for the DT URL.** New `DTRG_ALLOWED_HOSTS` env (comma-separated, `*.subdomain` wildcards supported). When set, the URL accepted from the form / API must match one of the patterns or `check_format_url` rejects it before any HTTP call goes out. Empty by default - on-prem deployments keep the previous "any host" behaviour.
- New env vars: `DTRG_API_RATE_LIMIT`, `DTRG_CVEPAAS_KEY`, `DTRG_ALLOWED_HOSTS`.

### Changed

- `pytest` runs in CI against Python 3.11, 3.12 and 3.13 (was only 3.12).
- `GetReportForm` reads `DTRG_URL` / `DTRG_TOKEN` per request inside `__init__` rather than at class definition time, so flipping the env at runtime takes effect on the next form render without restarting the process.
- `create_report` is now a thin orchestrator over named helpers (`_resolve_params`, `_load_project`, `_render_docx` / `_render_xlsx` / `_render_summary`). No behaviour change.

### Fixed

- **CVE-PaaS errors no longer abort the report.** Network failures, 5xx responses and malformed JSON from CVE-PaaS are now logged at WARNING and the report is rendered without enrichment for the affected batch (graceful degradation).

## [2.0.0]

### Breaking changes

- TLS verification of outbound calls to DT and CVE-PaaS is now ON by default. Self-signed test instances must opt out via `DTRG_VERIFY_TLS=false`.
- `DTRG_DEBUG=true` refuses to start when bound to a non-loopback address. Use `DTRG_HOST=127.0.0.1` (preferred) or set `DTRG_DEBUG_ALLOW_REMOTE=true` to confirm. The Werkzeug debugger is RCE-equivalent on a public bind.
- The form endpoints `/reports/get_report` and `/projects/get_all` now enforce the CSRF token that the form had been rendering all along but the server was never validating. External scripts POSTing to these routes will get 400 unless they include `csrf_token`. CI integrations should use the new `/api/v1/*` endpoints instead.
- The Docker image now runs as the non-root `dtrg` user. Mounted volumes that previously assumed root ownership need their permissions adjusted.
- Existing CI scripts hitting `/projects/get_all` outside the form flow no longer work — that endpoint is for the browser. Use `POST /api/v1/projects` with JSON.
- Long timeouts on the DT/CVE-PaaS HTTP client are gone. The default is now 120s (was 100/1000/10000 mixed). Override with `DTRG_HTTP_TIMEOUT` if a slow upstream needs more.
- `backend.get_projects` Python signature changed (now returns a `(body, total)` tuple). External callers of the function need to unpack.
- VEX-suppressed vulnerabilities (state `resolved` / `resolved_with_pedigree` / `false_positive` / `not_affected`) are now hidden from the report by default to match the DT UI. Set `DTRG_INCLUDE_SUPPRESSED=true` to keep them visible.
- DT 4.x or newer is required (the new VEX path calls `/api/v1/finding/project/{uuid}`, present since DT 3.x).

### Added

- `POST /api/v1/reports/get_report` — JSON-friendly endpoint that returns a ZIP report. Designed for CI; gated by `DTRG_API_KEY` when set; always CSRF-exempt.
- `POST /api/v1/projects` — JSON project listing for CI to resolve a UUID by name, with optional `searchText` / `pageSize` / `pageNumber` parameters and `X-Total-Count` response header.
- `GET /health` — liveness/readiness probe returning `{"status":"ok","version":...}`. Used by the new Docker `HEALTHCHECK` directive.
- OpenAPI 2.0 spec served at `/apispec.json`; Swagger UI at `/apidocs/` (powered by flasgger).
- Lazy-loaded project dropdown: select2 now runs in ajax mode against `/projects/get_all` with debounced search (300 ms) and on-scroll pagination, so DT instances with thousands of projects no longer freeze the form.
- VEX support: `analysis` state from the CycloneDX SBOM and `/api/v1/finding/project/{uuid}` is read on every report. The new `Analysis state` column in the `All issues` Excel sheet shows it; suppressed findings are filtered by default. `project_info.suppressedCount` is exposed in the docx Jinja context.
- Configurable graph depth via `DTRG_GRAPH_DEPTH` (default 3). The new `Graph level` column in the `Vulnerable dependencies` Excel sheet shows the per-component depth (1 = direct, 2 = its child, etc.).
- New env vars: `DTRG_API_KEY`, `DTRG_HOST`, `DTRG_DEBUG_ALLOW_REMOTE`, `DTRG_VERIFY_TLS`, `DTRG_HTTP_TIMEOUT`, `DTRG_SECRET_KEY`, `DTRG_INCLUDE_SUPPRESSED`, `DTRG_GRAPH_DEPTH`, `DTRG_PROJECTS_PAGE_SIZE`. All documented in the README.
- Pytest test suite under `tests/` (~75 tests covering validators, severity merge, graph traversal, VEX filtering, API auth) running on every push/PR via `.github/workflows/tests.yml`.
- `.dockerignore`.
- Subresource Integrity (`integrity` + `crossorigin`) on the select2 CDN assets.

### Changed

- The Flask `SECRET_KEY` falls back to `os.urandom` only when `DTRG_SECRET_KEY` is not set. Setting it stably is required for multi-worker deploys and sessions surviving restarts.
- Reports are now rendered into a per-request `tempfile.mkdtemp()` directory rather than fixed paths under `reports/`. Concurrent requests no longer race on shared file names.
- The graph HTML moved from an inline f-string in `app.py` to a Jinja template at `templates/graph.html`.
- Semgrep workflow migrated from the archived `returntocorp/semgrep-action` to `semgrep ci` inside the official `semgrep/semgrep` container.
- The Docker image installs Python requirements before copying source so layer caching survives source edits.

### Fixed

- VEX `False positive` markings made in the DT UI now reach the report. The CycloneDX `withVulnerabilities` variant does not always carry the analysis block; the report now also reads `/api/v1/finding/project/{uuid}` as the authoritative source.
- The dependency-graph traversal:
  - Used to crash with `'str' object has no attribute 'get'` when every child UUID was already-visited or missing — the `dependencies` field on the parent kept its raw UUID list and `update_tree` choked on it.
  - Cycles like `a → b → a` rendered `libA` twice; the visited set now seeds with direct-dep UUIDs.
  - `KeyError` when DT returned dependency lists with missing references.
- `get_severity` no longer crashes on `None` or unknown severity strings (previously a `KeyError` on something like `"none"`).
- Project metadata access no longer crashes on projects with missing `metrics`, `dependencies`, or vulnerability `priority` — `None`-chains were guarded.
- Project UUID parsed via regex so values without the `name version (uuid)` shape (e.g. a manually entered UUID via the API) no longer raise `IndexError`.
- DT API calls now use `res.raise_for_status()` + `res.json()` so HTTP errors surface directly instead of being masked by a downstream JSON-decode error.
- Two `f`-prefixed log strings that were not `f`-strings, so the placeholders never expanded.
- Removed the dead `if not isinstance(...): raise <returned value>` defensive branches that pylint had to silence with `raising-bad-type` — the validators they guard already raise on failure.

### Security

- `DTRG_API_KEY` (optional) gates `/api/v1/*`. Compared with `hmac.compare_digest`. Authentication accepts both `X-DTRG-Key` and `Authorization: Bearer ...` headers.
- CVE id flowing into the CVE-PaaS URL is restricted to canonical `CVE-YYYY-NNNN[N+]`, blocking URL-injection from a malformed upstream id.
- DT API token is redacted before being logged at `DEBUG`.
- Outbound HTTP timeouts unified at a sane default; the old 10000-second figure was DoS-shaped.
- `os.chdir` removed from the report path; concurrent requests no longer race on the process working directory.
