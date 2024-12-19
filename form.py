from flask_wtf import FlaskForm
from wtforms import SelectMultipleField, SelectField, StringField, SubmitField, validators


class GetReportForm(FlaskForm):
    """"main UI form"""
    url = StringField('URL')
    token = StringField('Token')
    project = SelectField("Project",
        choices=[("", "")],
        validators=[validators.InputRequired()])
    severities = SelectMultipleField('Severities (choose with "CTRL")',
        choices=[('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'), ('unassigned', 'Unassigned')],
        default=['critical', 'high'])
    report_type = SelectField('Report type', choices=[('word', 'Word'), ('excel', 'Excel')], default='word')
    submit = SubmitField('Get report')
