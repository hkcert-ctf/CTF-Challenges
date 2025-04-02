#!/usr/bin/env python3
import urllib.request
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("host", nargs="?", default="127.0.0.1", help="host to connect", type=str)
parser.add_argument("port", nargs="?", default=8080, help="port to connect", type=int)
args = parser.parse_args()

response = urllib.request.urlopen(f"http://{args.host}:{args.port}").read().decode("utf-8")

print(response)

if "hkcert22{flag}" in response:
    # ok
    exit(0)

# if flag not found, failed
exit(1)