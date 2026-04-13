FROM python:3.15.0a8-alpine3.23
RUN apk update && apk upgrade && apk add bash

COPY . /app
WORKDIR /app

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
