""" Forms """

from flask_wtf import FlaskForm
from wtforms import (
    SelectField,
    SelectMultipleField,
    StringField,
    SubmitField,
    validators,
)



class GetReportForm(FlaskForm):
    """" Main UI form """
    url = StringField("URL")
    token = StringField("Token")
    project = SelectField("Project",
        choices=[("", "")],
        validators=[validators.InputRequired()])
    severities = SelectMultipleField('Severities (choose with "CTRL")',
        choices=[("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                 ("low", "Low"), ("unassigned", "Unassigned")],
        default=["critical", "high"])
    report_type = SelectField("Report type",
        choices=[("word", "Word"), ("excel", "Excel")], default="word")
    submit = SubmitField("Get report")
