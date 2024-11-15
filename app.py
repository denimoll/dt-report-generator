from backend import report
from flask import Flask, render_template, request, send_file, flash
from flask_bootstrap import Bootstrap5
from form import GetReportForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'devsecops'
bootstrap = Bootstrap5(app)

@app.route('/', methods=['GET', 'POST'])
def index():
    form = GetReportForm()
    if form.is_submitted():
        result = request.form.to_dict(flat=False)
        req_report = report(result)
        if req_report == 'word':
            return send_file('./reports/result.docx', as_attachment=True) 
        elif req_report == 'excel':
            return send_file('./reports/result.xlsx', as_attachment=True)
        else:
            flash(req_report, 'danger')
    return render_template('index.html', form=form)

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
