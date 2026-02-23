# Protocol Fuzzing Writeup

## Problem Statement

Connecting to port 9999 of the target server, I discovered an unknown binary protocol. I need to use fuzz testing to understand the protocol format, complete authentication, and then read the flag.

## Approach to the Problem

### Step 1: Preliminary detection

First, connect to the server and you will receive an initial message:

```python
from pwn import *
s = remote("target", 9999)
data = s.recv(1024)
print(data)
# b'\xe6\x13\x044x\x00...\x00\x00)\x00\x00\x00Enter the "help" command to view available commands\n'
```

It can be seen from the initial message that:

- The first 4 bytes are magic numbers: `\xe6\x13\x04\x34`
- The 5th byte is the version number `0x78`
- followed by a timestamp, sequence number, length, and the actual message
- Each message ends with `\n`

### Step 2: Fuzz protocol header

Send random data for testing:

```python
s.send(b"AAAA" + b"\x00" * 16 + b"\n")
# Received: ERR_INVALID_MAGIC
```

Using the correct magic number but the wrong version:

```python
s.send(b"\xe6\x13\x04\x34" + b"\x01" + b"\x00" * 15 + b"\n")
# Received: ERR_UNSUPPORTED_VERSION
```

By observing the initial message, the version number is `0x78`:

```python
s.send(b"\xe6\x13\x04\x34" + b"\x78" + b"\x00" * 15 + b"\n")
# Received: ERR_INVALID_PACKET_TYPE
```

### Step 3: Analyze the protocol format

Through continuous fuzzing, the protocol format is gradually reconstructed:

| Field      | Offset      | Length          | Description                             |
| ---------- | ----------- | --------------- | --------------------------------------- |
| Magic      | 0           | 4               | Fixed `0xe6, 0x13, 0x04, 0x34`          |
| Version    | 4           | 1               | Protocol version `0x78`                 |
| Type       | 5           | 1               | Message type                            |
| Timestamp  | 6           | 8               | Unix timestamp UTC+8 (little-endian)    |
| Sequence   | 14          | 2               | Message sequence number (little-endian) |
| PayloadLen | 16          | 4               | Payload length (little-endian)          |
| Payload    | 20          | Variable length | Actual data                             |
| Newline    | End of line | 1               | Newline character `\n`                  |

Message type:

- 0x00: Initial Message (Init Message)
- 0x01: Handshake request
- 0x02: Handshake ACK
- 0x03: Command request (Command)
- 0x04: Command response (Response)
- 0xFF: Error response (Error)

Key points:

- The timestamp of the message sent by the client **must be consistent with the timestamp returned by the server in the previous message**
- **The sequence number of each sent and received message is incremented by 1, with the server always having an even number and the client always having an odd number**
- **Each message must have a newline character `\n` at the end**

### Step 4: Send the "help" command

According to the initial message prompt, send the help command (type=0x03):

```python
import struct

MAGIC = bytes([0xe6, 0x13, 0x04, 0x34])
VERSION = 0x78

def build_packet(ptype, payload, timestamp, seq):
    header = MAGIC
    header += struct.pack("B", VERSION)
    header += struct.pack("B", ptype)
    header += struct.pack("<Q", timestamp)  # little-endian
    header += struct.pack("<H", seq)        # little-endian
    header += struct.pack("<I", len(payload))  # little-endian
    return header + payload + b"\n"

# Server initial message seq=0, client's first message seq=1
packet = build_packet(0x03, b"help", server_timestamp, 1)
s.send(packet)
# Received response seq=2
```

Received response:

```
Available Commands:
help: prints this message
negotiate: Negotiate a key through Diffie–Hellman to enable encrypted communication
          (send your DH public key and receive server's DH public key)

readflag: show flag
```

### Step 5: Try to read the flag directly

```python
# The server's last response was seq=2, and the client's next one will be seq=3
packet = build_packet(0x03, b"readflag", server_timestamp, 3)
s.send(packet)
# Received: ERR_COMMUNICATION_NOT_ENCRYPTED (seq=4)
```

You need to negotiate the key through DH first!

### Step 6: Execute the "negotiate" command

```python
# seq=3
packet = build_packet(0x03, b"negotiate", server_timestamp, 3)
s.send(packet)
# Received: Please send a Handshake packet (type=0x01) containing your DH public key (seq=4)
```

### Step 7: DH Key Exchange

Use standard DH parameters (RFC 3526 Group 14):

```python
DH_P = int("FFFFFFFF...FFFFFFFF", 16)
DH_G = 2

# Generate client key pair
priv_key = secrets.randbelow(DH_P - 2) + 1
pub_key = pow(DH_G, priv_key, DH_P)
pub_key_bytes = pub_key.to_bytes((pub_key.bit_length() + 7) // 8, 'big')

# Send handshake request (type=0x01, seq=5)
packet = build_packet(0x01, pub_key_bytes, server_timestamp, 5)
s.send(packet)

# Receive server public key (seq=6)
resp = recv_packet(s)
server_pub_key = int.from_bytes(resp["payload"], 'big')

# Calculate shared secret key
shared_secret = pow(server_pub_key, priv_key, DH_P)
shared_key = hashlib.sha256(shared_secret.to_bytes(..., 'big')).digest()
```

### Step 8: Read the flag and decrypt it

After the negotiation is completed, send the readflag command:

```python
# seq=7
packet = build_packet(0x03, b"readflag", server_timestamp, 7)
s.send(packet)
resp = recv_packet(s)  # seq=8

# The flag is encrypted and requires decryption using AES-GCM
iv = resp["payload"][:12]
ciphertext = resp["payload"][12:]
cipher = AES.new(shared_key, AES.MODE_GCM, nonce=iv)
flag = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
print(flag)  # flag{...}
```

## Complete Exploit

See `solver.py`

## Knowledge Points

1. Protocol reversing and fuzzing
2. Binary protocol analysis (byte order handling)
3. Diffie-Hellman key exchange
4. AES-GCM authentication and encryption
5. Timestamp synchronization mechanism
6. Serial number parity check

## Flag

```
flag{pr0t0c0l_fuzz1ng_m4st3r}
```
