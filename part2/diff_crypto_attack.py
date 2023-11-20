"""
Script for differential cryptanalysis on a simple example of a block cipher
based on a 3-round simplified Feistle network combined with AES boxes.

The main idea is to understand an implement a differential cryptanalysis attack
to reveal the 4 bytes of the key in the third round.

The implementation of this example cipher is given in cipher.py.

Author: Dr. Marios O. Choudary
"""


import functools
import sys
import random
import string
import time
import itertools
import operator
import base64

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import array

from format_funcs import *
from cipher_server import *
from cipher import *

debug = False


def main():
    #################################################################################################
    # Task 1:
    # Generate input plaintext differentials with difference (xor) DeltaX in first four bytes of message
    # Here you should generate messages (64 bits, M = L | R, where each L and R has 32-bits, or 4 bytes)
    # that have a large differential (e.g. bits '11111111') in each of the bytes in L.
    # Note: you may use the same differential byte for all bytes in L (i.e. first four bytes of message)
    # but you should use some random value in the bytes of R (i.e. the last four bytes of the message).
    #################################################################################################
    deltax = b'1' * 32 + b'0' * 32
    deltaxh = bin2hex(deltax)
    print("deltaxh = " + deltaxh +"\n")
    M1 = []
    M2 = []
    C1 = []
    C2 = []
    for v in range(256):
        print("Generating plaintexts and ciphertexts for v = " + str(v) + "\n")

        m1 = functools.reduce(lambda a, b: a + b, [random.choice([b'1', b'0']) for _ in range(64)])
        m1h = bin2hex(m1)
        m2h = hexxor(m1h, deltaxh)
        m1 = m1h
        m2 = m2h

        print("Generated plaintexts m1= " + m1 + ", m2=" +
              m2 + ", with difference " + deltaxh + "\n")

        M1.append(m1)
        M2.append(m2)

        # Compute encryption for m1 and m2
        c1 = icc_enc_server(m1, False)
        c2 = icc_enc_server(m2, False)
        C1.append(c1)
        C2.append(c2)

    print("Finished generating differentials. We have " +
          str(len(C1)) + " message/ciphertext pairs\n")

    #################################################################################################
    # Task 2 (main attack):
    # Check all values of each byte of k3 until we get correct relation in E'.
    # Note that k3 only has 4 bytes.
    # Attack each byte of k3 until you get all 4 bytes and then you have obtained the entire key k3.
    #################################################################################################
    k3 = ''
    values = []

    for b in range(4):
        print("Attacking k3 for byte " + str(b) + "\n")
        for k in range(256):
            amount = 0
            for i in range(256):
                c1 = C1[i]
                c2 = C2[i]
                if c1 != 'Wrong len for m' and c2 != 'Wrong len for m':

                    c1b = hex2bin(c1)
                    c2b = hex2bin(c2)

                    c1_R = c1b[32 + b * 8 : 32 + (b + 1) * 8]
                    c2_R = c2b[32 + b * 8 : 32 + (b + 1) * 8]
                    c1_L = c1b[b * 8 : (b + 1) * 8]
                    c2_L = c2b[b * 8 : (b + 1) * 8]

                    R1 = bin2hex(c1_R)
                    L1 = bin2hex(c1_L)
                    R2 = bin2hex(c2_R)
                    L2 = bin2hex(c2_L)

                    X1 = hexxor(R1, int2hexstring(sbox[int(hexxor(int2hexstring(k), L1), 16)]))
                    X2 = hexxor(R2, int2hexstring(sbox[int(hexxor(int2hexstring(k), L2), 16)]))

                    deltay = hexxor(X1, X2)
                    if deltay == bin2hex(b'11111111'):
                        amount += 1
            if amount != 0:
                values.append((k, amount))

        values = sorted(values, key= lambda t: t[1])
        k3 += int2hexstring(values[len(values) - 1][0])


        #################################################################################################
        # For each possible key value of the current byte of k3:
        #
        # 1) Get the corresponding ciphertext bytes c1, c2 from C1 and C2, respectively,
        #    for all ciphertexts in the lists C1 and C2.
        #    Note that for each target byte of k3, you will need one byte from the first half of
        #    the ciphertext (L3) and one byte from the second half (R3).
        #
        # 2) Using the possible value of the byte of k3 and c1, respectively c2, determine the
        #    intermediate state E'(k3, c) by reversing the encryption process.
        #
        # 3) Given the intermediate states es1=E'(k3,c1), es2=E'(k3, c2) for all ciphertexts in C1, C2,
        #    obtain the output differential deltay = es1 XOR es2
        #
        # 4) Count the number of ciphertexts for which the output differential deltay is the expected one
        #    (in our case it should be the same as the input differential)
        #
        # 5) Retain as the correct key byte value, the one leading to the largest count of matching differentials.
        #
        #################################################################################################

    #################################################################################################
    # Task 3:
    # Decrypt the secret message using the full key (k = k1 | k2 | k3)
    #################################################################################################
    print("Full key k3 is: " + k3)
    key = 'aabbccddaabbccdd' + k3
    print("Full key is: " + key)
    c = '5cffd6a4f3329b86'
    print("Ciphertext to decrypt (in hex) is: " + c)

    m = icc_dec(key, c)
    print("Decryption of ciphertext " + c + " is: " + m)
    ms = hex2str(m)
    print("Plaintext in ASCII: " + ms)


if __name__ == "__main__":
    main()
