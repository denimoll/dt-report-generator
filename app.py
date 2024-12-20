import os
import secrets

from flask import Flask, flash, render_template, request, send_file
from flask_bootstrap import Bootstrap5

import backend
from form import GetReportForm

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
bootstrap = Bootstrap5(app)

@app.route('/', methods=['GET', 'POST'])
def index():
    """main UI logic"""
    form = GetReportForm()
    if form.is_submitted():
        result = request.form.to_dict(flat=False)
        req_report = backend.report(result)
        if req_report == 'word':
            return send_file('./reports/result.docx', as_attachment=True) 
        elif req_report == 'excel':
            return send_file('./reports/result.xlsx', as_attachment=True)
        else:
            flash(req_report, 'danger')
    return render_template('index.html', form=form)

@app.route("/get_projects", methods=["POST"])
def get_projects():
    return backend.get_projects(request.form.get("url"), request.form.get("token"))


if __name__ == "__main__":
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    app.run(host='0.0.0.0', debug=debug_mode)
