FROM ubuntu:focal-20240918

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y python3 python3-pip wkhtmltopdf && \
    apt-get clean

COPY ./src /app

COPY ./flag.txt /

RUN pip install -r requirements.txt

CMD ["python3", "main.py"]