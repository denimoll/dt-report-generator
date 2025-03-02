""" Forms """

from flask_wtf import FlaskForm
import os
from wtforms import (
    SelectField,
    StringField,
    PasswordField,
    SubmitField,
    validators,
)


class GetReportForm(FlaskForm):
    """" Main UI form """
    # for aaS
    atrributes = {
        "readonly": True,
        "placeholder": "The admin has already set the value"
    }

    url = StringField("URL", render_kw=atrributes if os.getenv("DTRG_URL") else {})
    token = PasswordField("Token", render_kw=atrributes if os.getenv("DTRG_TOKEN") else {})
    project = SelectField("Project",
        choices=[("", "")],
        validators=[validators.InputRequired()])
    submit = SubmitField("Get report")
