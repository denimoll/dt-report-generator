""" Forms """

import os

from flask_wtf import FlaskForm
from wtforms import PasswordField, SelectField, StringField, SubmitField, validators


class GetReportForm(FlaskForm):
    """" Main UI form for report generation """
    # for aaS
    attributes = {
        "readonly": True,
        "placeholder": "The admin has already set the value"
    }

    url = StringField("URL", render_kw=attributes if os.getenv("DTRG_URL") else {})
    token = PasswordField("Token", render_kw=attributes if os.getenv("DTRG_TOKEN") else {})
    project = SelectField("Project",
        choices=[("", "")],
        validators=[validators.InputRequired()])
    submit = SubmitField("Get report")
