FROM python:3.14.5-alpine3.23
RUN apk update && apk upgrade && apk add bash

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . /app

RUN addgroup -S dtrg && adduser -S dtrg -G dtrg && chown -R dtrg:dtrg /app
USER dtrg

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget -qO- "http://localhost:${DTRG_PORT:-5000}/health" >/dev/null || exit 1

ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
