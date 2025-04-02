FROM python:3.13.0-bookworm

RUN useradd -m hkcertuser
RUN echo "hkcert24{pay_blackb6a_10BTC_t0_activate_y0ur_b6acp+_n0w!}" > /home/hkcertuser/local.txt
RUN chmod 444 /home/hkcertuser/local.txt
RUN chown hkcertuser /home/hkcertuser/local.txt

WORKDIR /app
COPY src/ /app/
RUN pip install -r requirements.txt && rm requirements.txt

USER hkcertuser
CMD ["python3", "app.py"]