""" Main logic dependency track report generator """

import os
import secrets
import zipfile

import requests
from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   send_file, url_for)
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
def clear_tmp_files():
    """ Remove old files in reports dir """
    for filename in os.listdir("reports/"):
        if filename.split(".")[0] != "draft":
            try:
                os.remove(os.path.join("reports/", filename))
            except OSError as e:
                flash(str(e), "danger")

def create_zip(with_graph=False):
    """ Additional function for create final archive with all materials """
    os.chdir("reports/")
    zipf = zipfile.ZipFile("reports.zip", "w", zipfile.ZIP_DEFLATED)
    for file in ["result.docx", "result.xlsx"]:
        zipf.write(file)
    if with_graph:
        zipf.write("graph.html")
    zipf.close()
    os.chdir("..")
    return True

@app.route("/reports/get_report", methods=["POST"])
def get_report():
    """ API Endpoint /reports/get_report """
    clear_tmp_files()
    data = request.form.to_dict(flat=False)
    report = create_report(data)
    with_graph = create_graph(data)
    if isinstance(report, str) and create_zip(with_graph):
        return send_file("reports/reports.zip", as_attachment=True, download_name="%s.zip" % report)
    else:
        flash(str(report), "danger")
        return redirect(url_for("index"))


# PROJECTS GROUP
@app.route("/projects/get_all", methods=["POST"])
def get_all_projects():
    """ API Endpoint /projects/get_all """
    data = request.form.to_dict(flat=False)
    try:
        return get_projects(data.get("url")[0], data.get("token")[0])
    except (ValueError, ConnectionError, requests.exceptions.ConnectionError):
        flash("An internal error has occurred.", "danger")
        return jsonify(error_msg="An internal error has occurred"), 400


# GRAPH GROUP
def create_graph(data):
    """ Additional function for create graph in backend """
    graph = get_graph(data.get("url")[0], data.get("token")[0],
                      data.get("project")[0].split("(")[1].split(")")[0])
    if graph:
        with open ("reports/graph.html", "w", encoding="utf-8") as f:
            f.write(
                """<html>
                <head><link rel="stylesheet" href="resource://content-accessible/plaintext.css">
                </head><body><pre>%s</pre></body>
                </html>""" % graph)
        return True
    else:
        return False

@app.route("/dependencyGraph/get_graph", methods=["POST"])
def get_dependencyGraph():
    """ API Endpoint /dependencyGraph/get_graph """
    data = request.form.to_dict(flat=False)
    if create_graph(data):
        return render_template("reports/graph.html")
    else:
        return jsonify(graph=None), 404


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() in ["true", "1", "t"]
    port = int(os.getenv("FLASK_PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
