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
    after_this_request,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_bootstrap import Bootstrap5

from backend.dependency_graph import get_graph
from backend.projects import get_projects
from backend.reports import create_report
from form import GetReportForm

# Logging setup
logging.basicConfig(
    format="%(asctime)s - [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("DTRG_SECRET_KEY") or secrets.token_hex(16)
bootstrap = Bootstrap5(app)


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


# INDEX PAGE
@app.route("/", methods=["GET"])
def index():
    """ Index page """
    form = GetReportForm()
    return render_template("index.html", form=form)


# REPORTS GROUP
def create_zip(output_dir, with_graph=False):
    """ Bundle the rendered files inside output_dir into reports.zip """
    logger.info("Creating ZIP archive with report files")
    zip_path = os.path.join(output_dir, "reports.zip")
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for file in ["result.docx", "result.xlsx"]:
                zipf.write(os.path.join(output_dir, file), arcname=file)
            if with_graph:
                zipf.write(os.path.join(output_dir, "graph.html"), arcname="graph.html")
        logger.info("ZIP archive created successfully")
        return zip_path
    except OSError as e:
        logger.error(f"Error while creating ZIP: {e}")
        flash(str(e), "danger")
        return None

def _redact(form_data):
    """ Drop secret-bearing fields from form data before logging """
    return {k: ("<redacted>" if k in {"token", "csrf_token"} else v)
            for k, v in form_data.items()}

def _new_output_dir():
    """ Create a unique output directory for a single report request """
    return tempfile.mkdtemp(prefix="dtrg-")

def _build_report(config, output_dir):
    """ Run create_report + graph + zip and return (zip_path, name_or_error) """
    report, components = create_report(config, output_dir)
    if not isinstance(report, str):
        return None, report
    with_graph = create_graph(components, output_dir) if components else False
    zip_path = create_zip(output_dir, with_graph)
    if not zip_path:
        return None, "Failed to build report archive"
    return zip_path, report

@app.route("/reports/get_report", methods=["POST"])
def get_report():
    """ API Endpoint /reports/get_report """
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
        return send_file(zip_path, as_attachment=True, download_name=f"{report}.zip")
    logger.error(f"Report generation failed: {report}")
    flash(str(report), "danger")
    return redirect(url_for("index"))

@app.route("/api/v1/reports/get_report", methods=["POST"])
@require_api_key
def get_report_api():
    """ JSON-friendly entrypoint for CI: returns the ZIP directly """
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
        return jsonify(error=str(report)), 400
    return send_file(zip_path, as_attachment=True,
                     download_name=f"{report}.zip", mimetype="application/zip")


# PROJECTS GROUP
@app.route("/projects/get_all", methods=["POST"])
def get_all_projects():
    """ API Endpoint /projects/get_all """
    logger.info("Received request to fetch all projects")
    data = request.form.to_dict(flat=False)
    try:
        url = data.get("url")[0] if not os.getenv("DTRG_URL") else os.getenv("DTRG_URL")
        token = data.get("token")[0] if not os.getenv("DTRG_TOKEN") else os.getenv("DTRG_TOKEN")
        logger.debug(f"Fetching projects from: {url}")
        return get_projects(url, token)
    except (ValueError, ConnectionError, IndexError) as e:
        logger.error(f"Error fetching projects: {e}")
        flash(f"An internal error has occurred. {str(e)}", "danger")
        return jsonify(error_msg=f"An internal error has occurred. {str(e)}"), 400


# GRAPH GROUP
def create_graph(components, output_dir):
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
