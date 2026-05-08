# dt-report-generator (dtrg) <img width="30" src="./static/icon.svg"/>
## Main information
Tool for create reports from [Dependency Track](https://dependencytrack.org/) in Word (.docx) and Excel (.xlsx) formats.\
More information about tool and how to use it can be found in the articles on habr [1](https://habr.com/ru/articles/860536/), [2](https://habr.com/ru/articles/900276/) (rus).
## Getting started
### Installation and start
№1. Python
```
git clone <this repo>
pip install --upgrade pip
pip install -r requirements.txt
python ./app.py
```
№2. Docker
```
docker pull ghcr.io/denimoll/dt-report-generator:latest
docker run --name dtrg -d -p 5000:5000 ghcr.io/denimoll/dt-report-generator
```
### Usage
1. Open in browser [localhost:5000](http://localhost:5000)
2. Fill out the form:
    - URL - DT address (format "protocol"://"domain"). For example, [https://dependencytrack.org](https://dependencytrack.org). The path to the API is automatically substituted - */api/v1/*
    - Token - API key ([how to get](https://docs.dependencytrack.org/integrations/rest-api/))
    - Project - project ID (Object Identifier parameter in Project Details or identifier in the URL after ".../projects/")
3. Click "Get report"
4. Wait
## CI usage
For pipelines a JSON API is exposed alongside the form. It returns the same ZIP, but does not need a browser session and is suitable for `curl` from a build job.

Generate a report:
```
curl -fSL -o report.zip \
    -H "X-DTRG-Key: $DTRG_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"project":"<uuid>"}' \
    http://dtrg.internal:5000/api/v1/reports/get_report
```
List projects to look up a UUID:
```
curl -fsSL \
    -H "X-DTRG-Key: $DTRG_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{}' \
    http://dtrg.internal:5000/api/v1/projects | jq '.[] | {name, version, uuid}'
```
Notes:
- `url` and `token` can be omitted from the request body when `DTRG_URL` and `DTRG_TOKEN` are set in the dtrg environment.
- The endpoints are open by default. When the service is reachable beyond a trusted network, set `DTRG_API_KEY` so requests must present the same key in the `X-DTRG-Key` (or `Authorization: Bearer ...`) header.
- Errors come back as `{"error": "..."}` with a non-200 status, never as a redirect.
- These endpoints are deliberately CSRF-exempt (CI tooling has no session). The form endpoints (`/reports/get_report`, `/projects/get_all`) keep CSRF protection on; rely on `DTRG_API_KEY` and network controls for `/api/v1/*`.

## Advanced usage
You can set environment variable. A couple of examples: \
\
№1. dtrg as a service
```
export DTRG_URL="http://evil.com"
export DTRG_TOKEN="some_special_token"
```
№2. Vulnerability prioritization or enrichment
You must beside deploy [CVE-PaaS](https://github.com/denimoll/CVE-PaaS) tool. For every CVE dtrg send request for enrich vulnerability and get priority for fix. \
Important to know: this may slow down the final report preparation. Especially for large projects. But with repeated requests for the same vulnerability it will be faster.
```
export CVEPAAS_URL="http://evil.com"
```
№3. Custom port
```
export DTRG_PORT=5252
```
When use docker run container with this command:
```
docker run --name dtrg -d -p $DTRG_PORT:5000 ghcr.io/denimoll/dt-report-generator
```
№4. Show VEX-suppressed findings
By default dtrg honours VEX: a finding marked in DT as `resolved`, `resolved_with_pedigree`, `false_positive` or `not_affected` is dropped from the report so it matches what the DT UI shows. Set the variable below to keep them in the output and see their analysis state in the `All issues` sheet.
```
export DTRG_INCLUDE_SUPPRESSED=true
```

All environment variables:
* DTRG_URL - DT address
* DTRG_TOKEN - DT API key
* DTRG_PORT - dtrg port
* DTRG_HOST - bind address (default: 0.0.0.0)
* DTRG_DEBUG - dtrg (Flask) debug mode. Refuses to start when combined with a non-loopback DTRG_HOST unless DTRG_DEBUG_ALLOW_REMOTE=true is set, because the Werkzeug debugger can be used for remote code execution.
* DTRG_DEBUG_ALLOW_REMOTE - explicit override that allows DTRG_DEBUG=true together with a non-loopback DTRG_HOST. Use only in trusted networks.
* DTRG_VERIFY_TLS - verify TLS certificate of DT and CVE-PaaS (default: true; set to false only for self-signed test instances)
* DTRG_HTTP_TIMEOUT - timeout in seconds for outbound HTTP calls to DT and CVE-PaaS (default: 120)
* DTRG_SECRET_KEY - Flask secret key used to sign session cookies and CSRF tokens for the form endpoints (`/`, `/reports/get_report`, `/projects/get_all`). Set a stable value when running multiple workers or behind a reverse proxy so tokens stay valid across restarts. If unset, a random key is generated on each start.
* DTRG_API_KEY - shared secret required on the /api/v1/* endpoints. When unset (default) those endpoints are open and only network controls protect them; when set, callers must present the same value in an `X-DTRG-Key` or `Authorization: Bearer ...` header.
* DTRG_INCLUDE_SUPPRESSED - when `true`, vulnerabilities that DT considers suppressed via VEX (state `resolved` / `resolved_with_pedigree` / `false_positive` / `not_affected`) are still rendered in the report with their analysis state in the `All issues` sheet. Default `false`, which matches the DT UI.
* DTRG_GRAPH_DEPTH - max depth of the dependency graph traversal. Direct dependencies are level 1, their children level 2, etc. The level of each component is shown in column G of the `Vulnerable dependencies` sheet; components beyond the depth limit show an empty cell. Default 3.
* CVEPAAS_URL - [CVE-PaaS](https://github.com/denimoll/CVE-PaaS) address
## Development
Tests live under `tests/` and run with pytest:
```
pip install -r requirements-dev.txt
pytest -q
```
The same suite runs on every push/PR via `.github/workflows/tests.yml`.
## Roadmap
Planned functionality:
- [x] *Project search*. Simplify the search for projects via the provided link and token.
- [x] *Dependency tree*. Export the tree with vulnerable components marked.
- [x] *Release policy*. Create release rules and publish Docker images.
- [x] *Reports*. Add a text to docx when 0 vulns.
- [x] *Dashboards with overview information*. Visualize data in the form of various graphs for visual analysis.
- [x] *Icon*. Create an icon for tool and add a favicon.
- [x] *Secure use as a service*. Add the ability to define trusted addresses (SSRF exclusion) or disable URL and token selection by setting default values.
- [x] *Vulnerability prioritization*. Implement logic that will help assess which vulnerabilities require priority fixing.
- [x] *Docs*. Add a documentation or just more info in readme.md for advansed settings (like custom port, use specific version and etc.)
- [x] *VEX support*. Honour CycloneDX analysis state from DT so suppressed findings are dropped (or surfaced via DTRG_INCLUDE_SUPPRESSED) in the report.
- [x] *Tests*. Smoke/unit tests for validators, severity merge, graph traversal, VEX filter and the API auth paths, run on every PR.
- [ ] *Optimization*. Pagination + ajax-search for large project lists (so 10k+ projects in DT do not lock up the form).
- [x] *Graph*. Configurable traversal depth via `DTRG_GRAPH_DEPTH`; per-component level surfaced in the report.
- [ ] *Specification*. Add a swagger / more info for API Endpoint like parameters in and out.
