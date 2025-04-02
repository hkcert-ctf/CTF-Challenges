from base64 import b64decode
from secrets import token_hex
import subprocess
import os
import sys
import tempfile

FLAG = os.environ["FLAG"] if os.environ.get("FLAG") is not None else "hkcert24{test_flag}"

print("Encode your Go program in base64")
code = input(">> ")

with tempfile.TemporaryDirectory() as td:
    fn = token_hex(16)
    src = os.path.join(td, f"{fn}")
    with open(src+".go", "w") as f:
        f.write(b64decode(code).decode())    

    p = subprocess.run(["./fork", "build", "-o", td, src+".go"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) # renamed binary
    if p.returncode != 0:
        print(r"Fail to build ¯\_(ツ)_/¯")
        sys.exit(1)

    _ = subprocess.run([src], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if _.returncode == 0:
        print(r"You can write Go programs with no bugs, but I cannot give you the flag ¯\_(ツ)_/¯")
        sys.exit(1)

    if b"panic" in _.stderr:
        print("I am calm...")
        sys.exit(1)

    print(f"You are an experienced Go developer, here's your flag: {FLAG}")
    sys.exit(1)