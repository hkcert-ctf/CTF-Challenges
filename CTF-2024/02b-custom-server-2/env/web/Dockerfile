FROM ubuntu:jammy-20240911.1

WORKDIR /app

ENV DEBIAN_FRONTEND noninteractive

RUN apt update

RUN apt -y install gcc

COPY ./src .

COPY ./flag.txt /flag.txt

RUN gcc server.c -o server

RUN useradd -ms /bin/bash www

USER www

ENTRYPOINT ["/app/server"]