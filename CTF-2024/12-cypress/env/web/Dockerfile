FROM python:3.11-slim-buster

WORKDIR /app

COPY requirements.txt requirements.txt

ENV FLASK_APP=app/app.py

RUN pip3 install -r requirements.txt

COPY . .

CMD ["gunicorn", "-b", "0.0.0.0:80", "app.app:app"]