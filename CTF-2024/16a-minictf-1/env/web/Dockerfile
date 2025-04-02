FROM python:3.11-slim-buster

WORKDIR /app

COPY requirements.txt requirements.txt

ENV FLASK_APP=app/app.py

ENV FLAG_1=hkcert24{y0u_c4n_9r0up_unsp3c1f13d_4t7r1bu73s_fr0m_th3_4tt3mp7_m0d3l}
ENV FLAG_2=hkcert24{y0u_c4n_wr1t3_unsp3c1f13d_4t7r1bu73s_t0_th3_us3r_m0d3l}

RUN pip3 install -r requirements.txt

COPY . .

RUN flask db upgrade

CMD ["gunicorn", "-b", "0.0.0.0:80", "app.app:create_app()"]