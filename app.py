""" Main logic dependency track report generator """

import os
import secrets
import zipfile

from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   send_file, url_for)
from flask_bootstrap import Bootstrap5

from backend.dependency_graph import get_graph
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
    report, components = create_report(data)
    with_graph = create_graph(components) if components else False
    if isinstance(report, str) and create_zip(with_graph):
        return send_file("reports/reports.zip", as_attachment=True, download_name=f"{report}.zip")
    else:
        flash(str(report), "danger")
        return redirect(url_for("index"))


# PROJECTS GROUP
@app.route("/projects/get_all", methods=["POST"])
def get_all_projects():
    """ API Endpoint /projects/get_all """
    data = request.form.to_dict(flat=False)
    try:
        url = data.get("url")[0] if not os.getenv("DTRG_URL") else os.getenv("DTRG_URL")
        token = data.get("token")[0] if not os.getenv("DTRG_TOKEN") else os.getenv("DTRG_TOKEN")
        return get_projects(url, token)
    except (ValueError, ConnectionError) as e:
        flash(f"An internal error has occurred. {str(e)}", "danger")
        return jsonify(error_msg=f"An internal error has occurred. {str(e)}"), 400


# GRAPH GROUP
def create_graph(components):
    """ Additional function for create graph in backend """
    graph = get_graph(components)
    if graph:
        with open ("reports/graph.html", "w", encoding="utf-8") as f:
            f.write(
                f"""<html>
                <head><link rel="stylesheet" href="resource://content-accessible/plaintext.css">
                </head><body><pre>{graph}</pre></body>
                </html>""")
        return True
    else:
        return False


if __name__ == "__main__":
    debug_mode = os.getenv("DTRG_DEBUG", "False").lower() in ["true", "1", "t"]
    port = int(os.getenv("DTRG_PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
