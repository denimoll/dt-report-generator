FROM python:3.13.7-alpine3.22
RUN apk update && apk upgrade && apk add bash

COPY . /app
WORKDIR /app

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
