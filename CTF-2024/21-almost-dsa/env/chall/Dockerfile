FROM ubuntu:jammy-20221101

RUN apt-get update && apt-get install -y python3 python3-pip python3-venv socat
RUN python3 -m venv /home/ctfuser/venv

RUN /home/ctfuser/venv/bin/pip uninstall crypto
RUN /home/ctfuser/venv/bin/pip uninstall pycryptodome
RUN /home/ctfuser/venv/bin/pip install pycryptodome

WORKDIR /home/ctfuser
COPY *.py /home/ctfuser/
RUN python3 -m compileall /home/ctfuser/

ENV FLAG hkcert24{0n3_s1i9h1i3s7_m1s74k3_br34ks_4_cryp70sy573m}
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"stdbuf -i0 -o0 -e0 /home/ctfuser/venv/bin/python3 /home/ctfuser/chall.py"
