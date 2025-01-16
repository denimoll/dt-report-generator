""" Main logic dependency track report generator """

import os
import secrets

from flask import (Flask, flash, jsonify, redirect, render_template,
                   render_template_string, request, send_file, url_for)
from flask_bootstrap import Bootstrap5

from backend.dependencyGraph import get_graph
from backend.projects import get_projects
from backend.reports import create_report
from form import GetReportForm

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)
bootstrap = Bootstrap5(app)


# INDEX PAGE
@app.route("/", methods=["GET"])
def index():
    """ Index page """
    form = GetReportForm()
    return render_template("index.html", form=form)


# REPORTS GROUP
@app.route("/reports/get_report", methods=["POST"])
def get_report():
    """ API Endpoint /reports/get_report """
    result = request.form.to_dict(flat=False)
    req_report = create_report(result)
    if req_report == "word":
        return send_file("./reports/result.docx", as_attachment=True)
    elif req_report == "excel":
        return send_file("./reports/result.xlsx", as_attachment=True)
    else:
        flash(str(req_report), "danger")
    return redirect(url_for("index"))


# PROJECTS GROUP
@app.route("/projects/get_all", methods=["POST"])
def get_all_projects():
    """ API Endpoint /projects/get_all """
    data = request.form.to_dict(flat=False)
    try:
        return get_projects(data.get("url")[0], data.get("token")[0])
    except (ValueError, ConnectionError) as e:
        flash(str(e), "danger")
        return jsonify(error_msg=str(e)), 400

# GRAPH GROUP
@app.route("/dependencyGraph/get_graph", methods=["POST"])
def get_dependencyGraph():
    """ API Endpoint /dependencyGraph/get_graph """
    data = request.form.to_dict(flat=False)
    graph = get_graph(data.get("url")[0], data.get("token")[0], data.get("project")[0])
    if graph:
        source = """
        <html><head><link rel="stylesheet" href="resource://content-accessible/plaintext.css"></head><body><pre>
        {{graph}}
        </pre></body></html>"""
        return render_template_string(source, graph=graph)
    else:
        return jsonify(graph=None), 404


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() in ["true", "1", "t"]
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
