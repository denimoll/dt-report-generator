FROM python:3.15.0-alpine3.24
RUN apk update && apk upgrade && apk add bash

WORKDIR /app

COPY requirements.txt /app/
# Drop pip once the dependencies are in place: nothing at runtime shells out
# to it, and its vendored copies of msgpack / setuptools are the only CVE
# surface left in the image after the Alpine packages are upgraded.
RUN pip install --upgrade pip && pip install -r requirements.txt \
    && pip uninstall -y pip

COPY . /app

RUN addgroup -S dtrg && adduser -S dtrg -G dtrg && chown -R dtrg:dtrg /app
USER dtrg

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget -qO- "http://127.0.0.1:${DTRG_PORT:-5000}/health" >/dev/null || exit 1

ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
