from pwn import *
import base64 as b64
from time import sleep

GUEST_NAME = b"Anonymous"
ADMIN_NAME = b"Ephvuln"

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


LOCAL = False  # Local means that you run binary directly


if LOCAL:
# Complete this if you want to test locally
    r = process("part1\server.py")
else:
    r = remote("141.85.224.117", 1337)  # Complete this if changed

def read_options():
    """Reads server options menu."""
    r.readuntil(b"Input:")

def get_token():
    """Gets anonymous token as bytearray."""
    read_options()
    r.sendline(b"1")
    token = r.readline()[:-1]
    return b64.b64decode(token)

def login(tag):
    """Expects bytearray. Sends base64 tag."""
    r.readline()
    read_options()
    r.sendline(b"2")
    # sleep(0.01) # Uncoment this if server rate-limits you too hard
    r.sendline(b64.b64encode(tag))
    r.readuntil(b"Token:")
    response = r.readline().strip()
    return response


token = get_token()
print("[*] Acquired guest token: ", token)


start, end, prev_rasp = -1, -1, -1
for i in range(1, len(token)):
    payload = b'X' * i + token[i:]
    rasp = login(payload)
    if prev_rasp != -1 and prev_rasp != rasp:
        start = i - 1
        prev_rasp = -1
        break
    prev_rasp = rasp
print("[*] Server Public Banner start position: ", start)

for i in range(1, len(token)):
    payload = token[:i] + b'X' * (len(token) - i)
    # print(payload)
    rasp = login(payload)
    if prev_rasp != -1 and prev_rasp != rasp:
        # print(rasp, i)
        end = i
        break
    prev_rasp = rasp
print("[*] Server Public Banner end position: ", end)

msg = byte_xor(token, GUEST_NAME)
msg = byte_xor(msg, ADMIN_NAME)

print("[*] Creating payload ...")
for i in range(256):
    payload = msg + token[start:end] + i.to_bytes(1, 'big')
    response = login(payload)
    if b"CTF" in response:
       print("[*] Found flag:", response)
       break

r.close()