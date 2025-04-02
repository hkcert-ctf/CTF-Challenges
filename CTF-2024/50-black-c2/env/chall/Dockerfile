FROM ubuntu@sha256:6042500cf4b44023ea1894effe7890666b0c5c7871ed83a97c36c76ae560bb9b
RUN apt-get update && DEBIAN_FRONTEND=noninractive apt-get -y install \
        tini xinetd \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --no-create-home ctf && mkdir -p ctf

COPY ./src /home/ctf/
COPY ./app.xinetd /etc/xinetd.d/app
COPY ./src/flag.txt /

RUN chown -R root:root /home && \
    find /home -type d -exec chmod 555 {} \; && \
    find /home -type f -exec chmod 444 {} \;

RUN chmod 555 /home/ctf/chall

WORKDIR /home/ctf
EXPOSE 9999

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/sbin/xinetd","-dontfork"]
