""" Main logic dependency track report generator """

import hmac
import logging
import os
import secrets
import shutil
import tempfile
import zipfile
from functools import wraps

from flask import (
    Flask,
    Response,
    after_this_request,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flasgger import Swagger
from flask_bootstrap import Bootstrap5
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

from backend.dependency_graph import get_graph
from backend.param_validators import projects_page_size
from backend.projects import get_projects
from backend.reports import create_diff_report, create_report
from form import GetReportForm

# Logging setup
logging.basicConfig(
    format="%(asctime)s - [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger(__name__)

__version__ = "2.1.0"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("DTRG_SECRET_KEY") or secrets.token_hex(16)
bootstrap = Bootstrap5(app)
csrf = CSRFProtect(app)

# Rate limit on /api/v1/* only. Empty DTRG_API_RATE_LIMIT disables.
# Form routes / probes / Swagger are not limited.
_API_RATE_LIMIT = os.getenv("DTRG_API_RATE_LIMIT", "60/minute").strip()
limiter = Limiter(get_remote_address, app=app, default_limits=[],
                  storage_uri="memory://")


@app.errorhandler(429)
def _ratelimit_json(err):
    """ Return JSON for /api/v1/* clients (default Flask-Limiter is HTML) """
    if request.path.startswith("/api/v1/"):
        return jsonify(error="rate_limited", description=str(err.description)), 429
    return err


def _api_limit():
    """ Decorator that applies the configured rate limit, or no-op when empty """
    if not _API_RATE_LIMIT:
        return lambda view: view
    return limiter.limit(_API_RATE_LIMIT)

# OpenAPI / Swagger UI at /apidocs/, raw spec at /apispec.json.
swagger = Swagger(app, config={
    "headers": [],
    "specs": [{
        "endpoint": "apispec",
        "route": "/apispec.json",
        "rule_filter": lambda rule: True,
        "model_filter": lambda tag: True,
    }],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/",
}, template={
    "swagger": "2.0",
    "info": {
        "title": "dt-report-generator API",
        "description": "Generate Dependency-Track reports from a browser form "
                       "or from CI. The /api/v1/* endpoints are JSON, "
                       "CSRF-exempt, and gated by DTRG_API_KEY when set.",
        "version": "1.0",
    },
    "securityDefinitions": {
        "ApiKey": {
            "type": "apiKey",
            "in": "header",
            "name": "X-DTRG-Key",
            "description": "DTRG_API_KEY value. Required only if the env var is set.",
        },
        "Bearer": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "'Bearer <DTRG_API_KEY>'. Alternative to X-DTRG-Key.",
        },
    },
})


def _presented_api_key():
    """ Pull the dtrg API key from X-DTRG-Key or Authorization: Bearer ... """
    header = request.headers.get("X-DTRG-Key")
    if header:
        return header
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return ""

def require_api_key(view):
    """ Gate a route on DTRG_API_KEY when the env var is set """
    @wraps(view)
    def wrapper(*args, **kwargs):
        expected = os.getenv("DTRG_API_KEY") or ""
        if expected:
            presented = _presented_api_key()
            if not presented or not hmac.compare_digest(presented, expected):
                logger.warning("API call rejected: invalid or missing DTRG_API_KEY")
                return jsonify(error="unauthorized"), 401
        return view(*args, **kwargs)
    return wrapper


# PROBES
@app.route("/health", methods=["GET"])
def health():
    """Liveness/readiness probe.
    ---
    tags:
      - probe
    produces:
      - application/json
    responses:
      200:
        description: Service is up. Returns the running version.
        schema:
          type: object
          properties:
            status:
              type: string
              example: ok
            version:
              type: string
              example: 2.0.0
    """
    return jsonify(status="ok", version=__version__)


# INDEX PAGE
@app.route("/", methods=["GET"])
def index():
    """Render the HTML form for browser users.
    ---
    tags:
      - browser
    produces:
      - text/html
    responses:
      200:
        description: HTML page with the report-generation form.
    """
    form = GetReportForm()
    return render_template("index.html",
        form=form,
        has_env_url=bool(os.getenv("DTRG_URL")),
        has_env_token=bool(os.getenv("DTRG_TOKEN")))


# REPORTS GROUP
def _create_zip(output_dir, with_graph=False):
    """ Bundle the rendered files inside output_dir into reports.zip """
    logger.info("Creating ZIP archive with report files")
    zip_path = os.path.join(output_dir, "reports.zip")
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for file in ["result.docx", "result.xlsx", "summary.json"]:
                src = os.path.join(output_dir, file)
                if os.path.exists(src):
                    zipf.write(src, arcname=file)
            if with_graph:
                zipf.write(os.path.join(output_dir, "graph.html"), arcname="graph.html")
        logger.info("ZIP archive created successfully")
        return zip_path
    except OSError as e:
        logger.error(f"Error while creating ZIP: {e}")
        flash("Failed to build report archive.", "danger")
        return None

def _redact(form_data):
    """ Drop secret-bearing fields from form data before logging """
    return {k: ("<redacted>" if k in {"token", "csrf_token"} else v)
            for k, v in form_data.items()}

def _new_output_dir():
    """ Create a unique output directory for a single report request """
    return tempfile.mkdtemp(prefix="dtrg-")

def _safe_download_name(report):
    """ Sanitize the report-name string before it lands in Content-Disposition.

    `report` is built from the DT project name + version + date. The DT
    project name is operator-controlled but flows from an external system,
    so we run it through werkzeug's secure_filename to drop any path
    separators or odd unicode before sending it as a header.
    """
    safe = secure_filename(f"{report}.zip")
    return safe or "report.zip"

# Generic message returned to clients when report generation fails. The
# actual exception is logged; we do not surface its str() to keep
# CodeQL py/stack-trace-exposure happy and to avoid accidental leaks
# when validators evolve to embed contextual data.
_GENERIC_REPORT_FAILURE = "Report generation failed. Check server logs for details."

def _build_report(config, output_dir):
    """ Run create_report + graph + zip and return (zip_path, name_or_error) """
    report, components = create_report(config, output_dir)
    if not isinstance(report, str):
        return None, report
    with_graph = _create_graph(components, output_dir) if components else False
    zip_path = _create_zip(output_dir, with_graph)
    if not zip_path:
        return None, "Failed to build report archive"
    return zip_path, report

def _build_diff(config_a, config_b, output_dir):
    """ Run create_diff_report + zip and return (zip_path, name_or_error) """
    report, _ = create_diff_report(config_a, config_b, output_dir)
    if not isinstance(report, str):
        return None, report
    zip_path = _create_zip(output_dir, with_graph=False)
    if not zip_path:
        return None, "Failed to build report archive"
    return zip_path, report

@app.route("/reports/get_report", methods=["POST"])
def get_report():
    """Browser form submission. Prefer /api/v1/reports/get_report from CI.
    ---
    tags:
      - browser
    consumes:
      - application/x-www-form-urlencoded
    produces:
      - application/zip
      - text/html
    parameters:
      - in: formData
        name: csrf_token
        required: true
        type: string
        description: Token rendered into the form by Flask-WTF. Required.
      - in: formData
        name: url
        type: string
      - in: formData
        name: token
        type: string
      - in: formData
        name: project
        type: string
        description: '"name version (uuid)" as produced by the form select.'
    responses:
      200:
        description: ZIP archive with the rendered reports.
      302:
        description: Redirect back to the form on validation failure.
      400:
        description: CSRF token missing or invalid.
    """
    logger.info("Received request to generate report")
    output_dir = _new_output_dir()

    @after_this_request
    def _cleanup(response):
        response.call_on_close(lambda: shutil.rmtree(output_dir, ignore_errors=True))
        return response

    data = request.form.to_dict(flat=False)
    logger.debug(f"Form data received: {_redact(data)}")
    zip_path, report = _build_report(data, output_dir)
    if zip_path:
        logger.info("Report generation successful. Sending ZIP file")
        return send_file(zip_path, as_attachment=True,
                         download_name=_safe_download_name(report))
    logger.error(f"Report generation failed: {report}")
    flash(_GENERIC_REPORT_FAILURE, "danger")
    return redirect(url_for("index"))

@app.route("/api/v1/reports/get_report", methods=["POST"])
@csrf.exempt
@_api_limit()
@require_api_key
def get_report_api():
    """Generate a DT report and return it as a ZIP.
    ---
    tags:
      - api
    security:
      - ApiKey: []
      - Bearer: []
    consumes:
      - application/json
    produces:
      - application/zip
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - project
          properties:
            url:
              type: string
              description: DT instance URL. Optional when DTRG_URL is set.
              example: https://dependencytrack.example.com
            token:
              type: string
              description: DT API key. Optional when DTRG_TOKEN is set.
            project:
              type: string
              description: DT project UUID.
              example: 00000000-0000-0000-0000-000000000000
    responses:
      200:
        description: ZIP archive with result.docx, result.xlsx, summary.json and graph.html.
      400:
        description: Validation error (missing field or upstream rejected).
        schema:
          type: object
          properties:
            error:
              type: string
      401:
        description: DTRG_API_KEY is set and the request did not present it.
        schema:
          type: object
          properties:
            error:
              type: string
              example: unauthorized
    """
    logger.info("Received API request to generate report")
    body = request.get_json(silent=True) or {}
    if not body and request.form:
        body = request.form.to_dict(flat=True)
    config = {k: [str(body[k])] for k in ("url", "token", "project") if body.get(k)}
    logger.debug(f"API report request: {_redact(config)}")

    output_dir = _new_output_dir()

    @after_this_request
    def _cleanup(response):
        response.call_on_close(lambda: shutil.rmtree(output_dir, ignore_errors=True))
        return response

    zip_path, report = _build_report(config, output_dir)
    if not zip_path:
        logger.error(f"API report generation failed: {report}")
        return jsonify(error=_GENERIC_REPORT_FAILURE), 400
    return send_file(zip_path, as_attachment=True,
                     download_name=_safe_download_name(report),
                     mimetype="application/zip")

@app.route("/reports/diff", methods=["POST"])
def get_diff_report():
    """Browser form submission for a project-version diff.
    ---
    tags:
      - browser
    consumes:
      - application/x-www-form-urlencoded
    produces:
      - application/zip
      - text/html
    parameters:
      - in: formData
        name: csrf_token
        required: true
        type: string
      - in: formData
        name: url
        type: string
      - in: formData
        name: token
        type: string
      - in: formData
        name: project
        type: string
        description: 'Project A: "name version (uuid)" as produced by the form select.'
      - in: formData
        name: project_b
        type: string
        description: 'Project B: same shape; the diff is "from A to B".'
    responses:
      200:
        description: ZIP archive with the diff result.xlsx and summary.json.
      302:
        description: Redirect back to the form on validation failure.
      400:
        description: CSRF token missing or invalid.
    """
    logger.info("Received request to generate diff report")
    output_dir = _new_output_dir()

    @after_this_request
    def _cleanup(response):
        response.call_on_close(lambda: shutil.rmtree(output_dir, ignore_errors=True))
        return response

    data = request.form.to_dict(flat=False)
    logger.debug(f"Diff form data received: {_redact(data)}")
    config_a = {
        "url": data.get("url"),
        "token": data.get("token"),
        "project": data.get("project"),
    }
    config_b = {
        "url": data.get("url"),
        "token": data.get("token"),
        "project": data.get("project_b"),
    }
    zip_path, report = _build_diff(config_a, config_b, output_dir)
    if zip_path:
        logger.info("Diff report generation successful. Sending ZIP file")
        return send_file(zip_path, as_attachment=True,
                         download_name=_safe_download_name(report))
    logger.error(f"Diff report generation failed: {report}")
    flash(_GENERIC_REPORT_FAILURE, "danger")
    return redirect(url_for("index"))

@app.route("/api/v1/reports/diff", methods=["POST"])
@csrf.exempt
@_api_limit()
@require_api_key
def get_diff_report_api():
    """Generate a diff report between two DT projects and return it as a ZIP.
    ---
    tags:
      - api
    security:
      - ApiKey: []
      - Bearer: []
    consumes:
      - application/json
    produces:
      - application/zip
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - projectA
            - projectB
          properties:
            url:
              type: string
              description: DT instance URL. Optional when DTRG_URL is set.
            token:
              type: string
              description: DT API key. Optional when DTRG_TOKEN is set.
            projectA:
              type: string
              description: Baseline DT project UUID.
              example: 00000000-0000-0000-0000-000000000001
            projectB:
              type: string
              description: Comparison DT project UUID; diff is "from A to B".
              example: 00000000-0000-0000-0000-000000000002
    responses:
      200:
        description: ZIP archive with the diff result.xlsx and summary.json.
      400:
        description: Validation error (missing field or upstream rejected).
        schema:
          type: object
          properties:
            error:
              type: string
      401:
        description: DTRG_API_KEY is set and the request did not present it.
        schema:
          type: object
          properties:
            error:
              type: string
              example: unauthorized
    """
    logger.info("Received API request to generate diff report")
    body = request.get_json(silent=True) or {}
    if not body and request.form:
        body = request.form.to_dict(flat=True)
    base = {k: [str(body[k])] for k in ("url", "token") if body.get(k)}
    config_a = dict(base)
    config_b = dict(base)
    if body.get("projectA"):
        config_a["project"] = [str(body["projectA"])]
    if body.get("projectB"):
        config_b["project"] = [str(body["projectB"])]
    logger.debug(f"API diff request: {_redact(config_a)} vs {_redact(config_b)}")

    output_dir = _new_output_dir()

    @after_this_request
    def _cleanup(response):
        response.call_on_close(lambda: shutil.rmtree(output_dir, ignore_errors=True))
        return response

    zip_path, report = _build_diff(config_a, config_b, output_dir)
    if not zip_path:
        logger.error(f"API diff report generation failed: {report}")
        return jsonify(error=_GENERIC_REPORT_FAILURE), 400
    return send_file(zip_path, as_attachment=True,
                     download_name=_safe_download_name(report),
                     mimetype="application/zip")


# PROJECTS GROUP
@app.route("/projects/get_all", methods=["POST"])
def get_all_projects():
    """AJAX project list for the browser form. Prefer /api/v1/projects from CI.
    ---
    tags:
      - browser
    consumes:
      - application/x-www-form-urlencoded
    produces:
      - application/json
    parameters:
      - in: formData
        name: csrf_token
        required: true
        type: string
      - in: formData
        name: url
        type: string
      - in: formData
        name: token
        type: string
      - in: formData
        name: searchText
        type: string
        description: Optional substring filter forwarded to DT.
      - in: formData
        name: pageNumber
        type: integer
        description: 1-based page number. Page size is fixed by DTRG_PROJECTS_PAGE_SIZE.
    responses:
      200:
        description: |
          DT project list for the requested page. The X-Total-Count header
          carries the total number of matching projects.
      400:
        description: CSRF or upstream error.
    """
    logger.info("Received request to fetch all projects")
    data = request.form.to_dict(flat=False)
    try:
        url = data.get("url")[0] if not os.getenv("DTRG_URL") else os.getenv("DTRG_URL")
        token = data.get("token")[0] if not os.getenv("DTRG_TOKEN") else os.getenv("DTRG_TOKEN")
        search_text = (data.get("searchText") or [""])[0]
        try:
            page_number = max(int((data.get("pageNumber") or ["1"])[0]), 1)
        except (ValueError, TypeError):
            page_number = 1
        logger.debug(f"Fetching projects from: {url} "
                     f"(page={page_number}, search={search_text!r})")
        page_size = projects_page_size()
        body, total = get_projects(url, token,
                                   search_text=search_text,
                                   page_size=page_size,
                                   page_number=page_number)
        if isinstance(body, dict):
            return jsonify(body), 502
        response = Response(body, mimetype="application/json")
        response.headers["X-Total-Count"] = str(total)
        response.headers["X-Page-Size"] = str(page_size)
        return response
    except (ValueError, ConnectionError, IndexError) as e:
        logger.error(f"Error fetching projects: {e}")
        flash("An internal error has occurred while fetching projects.", "danger")
        return jsonify(error_msg="An internal error has occurred."), 400

@app.route("/api/v1/projects", methods=["POST"])
@csrf.exempt
@_api_limit()
@require_api_key
def get_all_projects_api():
    """List Dependency-Track projects.
    ---
    tags:
      - api
    security:
      - ApiKey: []
      - Bearer: []
    consumes:
      - application/json
    produces:
      - application/json
    parameters:
      - in: body
        name: body
        required: false
        schema:
          type: object
          properties:
            url:
              type: string
              description: DT instance URL. Optional when DTRG_URL is set.
            token:
              type: string
              description: DT API key. Optional when DTRG_TOKEN is set.
            searchText:
              type: string
              description: Optional substring filter forwarded to DT.
            pageSize:
              type: integer
              description: |
                Optional. Number of projects per page (default returns
                everything DT has up to 99999 to preserve previous CI
                behaviour).
            pageNumber:
              type: integer
              description: Optional. 1-based page number (default 1).
    responses:
      200:
        description: |
          JSON array of DT project objects (forwarded from DT). The
          X-Total-Count response header carries the total number of
          projects matching the search.
      400:
        description: Missing url/token or non-integer pagination.
        schema:
          type: object
          properties:
            error:
              type: string
      401:
        description: DTRG_API_KEY is set and the request did not present it.
      502:
        description: Upstream DT request failed.
        schema:
          type: object
          properties:
            error:
              type: string
    """
    body = request.get_json(silent=True) or {}
    if not body and request.form:
        body = request.form.to_dict(flat=True)
    url = os.getenv("DTRG_URL") or body.get("url") or ""
    token = os.getenv("DTRG_TOKEN") or body.get("token") or ""
    if not url or not token:
        return jsonify(error="url and token are required"), 400

    search_text = str(body.get("searchText") or "")
    try:
        page_size = int(body["pageSize"]) if body.get("pageSize") else 99999
        page_number = max(int(body["pageNumber"]) if body.get("pageNumber") else 1, 1)
    except (ValueError, TypeError):
        return jsonify(error="pageSize and pageNumber must be integers"), 400

    logger.debug(f"API projects request for: {url} "
                 f"(page={page_number}, size={page_size}, search={search_text!r})")
    result, total = get_projects(url, token,
                                 search_text=search_text,
                                 page_size=page_size,
                                 page_number=page_number)
    if isinstance(result, dict):
        return jsonify(result), 502
    response = Response(result, mimetype="application/json")
    response.headers["X-Total-Count"] = str(total)
    return response


# GRAPH GROUP
def _create_graph(components, output_dir):
    """ Render the dependency graph HTML into output_dir """
    logger.info("Generating graph from components")
    graph = get_graph(components)
    if graph:
        rendered = render_template("graph.html", graph=graph)
        with open(os.path.join(output_dir, "graph.html"), "w", encoding="utf-8") as f:
            f.write(rendered)
        logger.info("Graph HTML saved successfully")
        return True
    logger.warning("Graph data was empty; skipping HTML generation")
    return False


if __name__ == "__main__":
    debug_mode = os.getenv("DTRG_DEBUG", "False").lower() in ["true", "1", "t"]
    port = int(os.getenv("DTRG_PORT", "5000"))
    host = os.getenv("DTRG_HOST", "0.0.0.0")
    allow_remote_debug = os.getenv("DTRG_DEBUG_ALLOW_REMOTE", "False").lower() in [
        "true", "1", "t"
    ]

    # Werkzeug debugger exposes a remote code execution path via the PIN
    # console. Refuse to combine debug mode with a non-loopback bind unless
    # operators explicitly opt in.
    if debug_mode and host not in ("127.0.0.1", "localhost") and not allow_remote_debug:
        raise SystemExit(
            "DTRG_DEBUG=true is unsafe with a non-loopback DTRG_HOST. "
            "Set DTRG_HOST=127.0.0.1 or DTRG_DEBUG_ALLOW_REMOTE=true to confirm."
        )

    # Set logging level based on debug mode
    log_level = logging.DEBUG if debug_mode else logging.INFO
    logging.getLogger().setLevel(log_level)
    logger.info(f"Starting app on {host}:{port} with debug={debug_mode}")

    app.run(host=host, port=port, debug=debug_mode)
