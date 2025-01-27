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
    submit = SubmitField("Get report")
