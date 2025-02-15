#!/usr/bin/python3
import base64 as b64

from Crypto import Random
from Crypto.Cipher import AES

# from secretz import *

options_txt = """Options:
1. Get guest token
2. Login
3. Exit
Input:"""

welcome_txt = """Welcome to SRY, most confidential platform with top-notch integrity.
To get public data login as guest."""

GUEST_NAME = b"Anonymous"
AES_KEY_SIZE = 16


def byte_xor(txt, rnd):
    return bytes(a ^ b for a, b in zip(txt, rnd))


class Crypt:
    def __init__(self):
        # 16 biti, ramane la fel
        KEY = Random.get_random_bytes(AES_KEY_SIZE)
        # 16 biti, ramane la fel
        self.IV = Random.get_random_bytes(AES_KEY_SIZE)
        # AES ECB
        self.C = AES.new(KEY, AES.MODE_ECB)
        # e literally the same????
        self.INTEGRITY = AES.new(KEY, AES.MODE_ECB)

    def getIntegrity(self, plain):
        # b'\x00' * (key_size - len(plain)) + plain
        # dar asta inseamna ca plain <= key_size
        # daca len(plain) == key_size ---> o sa am E(plain)[INTEGRITY_LEN]
        return self.INTEGRITY.encrypt(b'\x00' * (AES_KEY_SIZE - len(plain)) + plain)[0:INTEGRITY_LEN]

    def encrypt(self, plain):
        # E(IV) ^ plain + BANNER + integrity(plain)
        rnd = self.C.encrypt(self.IV)
        cipher = byte_xor(plain, rnd) + SERVER_PUBLIC_BANNER + self.getIntegrity(plain)
        return cipher

    def decrypt(self, input):
        rnd = self.C.encrypt(self.IV)
        secret_len = INTEGRITY_LEN + len(SERVER_PUBLIC_BANNER)
        cipher, secret, tag = input[:-secret_len], input[-secret_len:-INTEGRITY_LEN], input[-INTEGRITY_LEN:]
        plain = byte_xor(cipher, rnd)
        if secret != SERVER_PUBLIC_BANNER:
            return -1
        if self.getIntegrity(plain) != tag:
            return None

        return plain


def get_guest_token():
    global C
    token = C.encrypt(GUEST_NAME)
    print(b64.b64encode(token).decode('raw_unicode_escape'))


def login():
    global C
    try:
        s = input("Token:")  # Python3. Don't get funny RCE ideas
        cipher = b64.b64decode(s)

        if(len(cipher) > 16):
            print("Tokens must be smaller than 16 bytes!")
        plain = C.decrypt(cipher)

        if plain == -1:
            # aici nu are server banner
            print("Wrong server secret!")
        elif plain == None:
            # aici nu a mers integrity
            print("Failed integrity check!")
        elif plain == GUEST_NAME:
            print("Secret:", "No secrets for anonymous")
        elif plain == b"Ephvuln":
            print("Secret:", FLAG)
        else:
            print("I don't have an answer for", plain.decode('utf-8'))
    except:
        print("No h3k1ng allowed")
        exit()


def invalid():
    print("! Invalid option.")


def menu():
    global C
    C = Crypt()

    print(welcome_txt)
    while True:
        print(options_txt, end='')
        switch = {
            "1": get_guest_token,
            "2": login,
            "3": exit
        }
        func = switch.get(input(), invalid)
        func()
        print()


if __name__ == "__main__":
    menu()

# deci stiu
# AES(IV) ^ GUEST_NAME + Banner + Integrity("0s" * key - plain + plain)[integrity len]
# ---> fac xor dintre bucata si GUEST_NAME == AES(IV)
#
#
#
#
#
#
#
#
#