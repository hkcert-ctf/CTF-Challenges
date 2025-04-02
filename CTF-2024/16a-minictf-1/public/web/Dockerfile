FROM python:3.11-slim-buster

WORKDIR /app

COPY requirements.txt requirements.txt

ENV FLASK_APP=app/app.py

ENV FLAG_1=hkcert24{this_is_a_test_flag_1}
ENV FLAG_2=hkcert24{this_is_a_test_flag_2}

RUN pip3 install -r requirements.txt

COPY . .

RUN flask db upgrade

CMD ["gunicorn", "-b", "0.0.0.0:80", "app.app:create_app()"]