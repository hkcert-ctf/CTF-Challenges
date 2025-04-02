FROM python:3.11-slim-bullseye

RUN apt update && apt install -y socat curl

WORKDIR /app
COPY fork main.py /app/
RUN curl -o go1.22.1.linux-amd64.tar.gz https://dl.google.com/go/go1.22.1.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz \
    && rm go1.22.1.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin

EXPOSE 3000

CMD socat TCP-LISTEN:3000,fork,reuseaddr,end-close EXEC:"python3 -u main.py",pty,stderr,echo=0