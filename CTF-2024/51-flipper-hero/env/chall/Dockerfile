FROM ubuntu:latest

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install \
        qemu-system-x86 tini xinetd lsof \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --no-create-home ctf && mkdir -p ctf

COPY ./src /home/ctf/
COPY ./app.xinetd /etc/xinetd.d/app

RUN chown -R root:root /home && \
    find /home -type d -exec chmod 555 {} \; && \
    find /home -type f -exec chmod 444 {} \;

RUN chmod 555 /home/ctf/run.sh

WORKDIR /home/ctf
EXPOSE 9999

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/sbin/xinetd","-dontfork"]
