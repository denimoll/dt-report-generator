""" Forms """

import os

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    validators,
)


# Sentinel render_kw applied to URL/Token when the corresponding DTRG_*
# env var is set, so the form makes it visible that an admin has pinned
# the value and there is nothing for the user to fill in.
_AAS_RENDER_KW = {
    "readonly": True,
    "placeholder": "The admin has already set the value",
}


class GetReportForm(FlaskForm):
    """" Main UI form for report generation """

    url = StringField("URL")
    token = PasswordField("Token")
    project = SelectField("Project",
        choices=[("", "")],
        validators=[validators.InputRequired()])
    compare = BooleanField("Compare with another version")
    project_b = SelectField("Project B",
        choices=[("", "")],
        validators=[validators.Optional()])
    submit = SubmitField("Get report")

    def __init__(self, *args, **kwargs):
        # Read DTRG_URL / DTRG_TOKEN per request rather than at class
        # definition time, so flipping the env at runtime takes effect
        # on the next form render without restarting the process.
        super().__init__(*args, **kwargs)
        if os.getenv("DTRG_URL"):
            self.url.render_kw = _AAS_RENDER_KW
        if os.getenv("DTRG_TOKEN"):
            self.token.render_kw = _AAS_RENDER_KW
