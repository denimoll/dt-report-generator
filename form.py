""" Forms """

from flask_wtf import FlaskForm
from wtforms import (
    SelectField,
    StringField,
    PasswordField,
    SubmitField,
    validators,
)


class GetReportForm(FlaskForm):
    """" Main UI form """
    url = StringField("URL")
    token = PasswordField("Token")
    project = SelectField("Project",
        choices=[("", "")],
        validators=[validators.InputRequired()])
    submit = SubmitField("Get report")
