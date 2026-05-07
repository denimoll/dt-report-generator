FROM python:3.14.4-alpine3.23
RUN apk update && apk upgrade && apk add bash

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . /app

RUN addgroup -S dtrg && adduser -S dtrg -G dtrg && chown -R dtrg:dtrg /app
USER dtrg

ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
