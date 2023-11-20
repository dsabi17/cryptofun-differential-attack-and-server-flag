"""
Script for implementation of our simple example of a block cipher
based on a 3-round simplified Feistle network combined with AES boxes.

The implementation of this example cipher is given below.

Author: Dr. Marios O. Choudary
"""

from pwn import remote

LOCAL = False  # If true, it uses the local implementation and **your** custom key
if LOCAL:
    from cipher import *
    key = ...  # REDACTED
else:
    # TODO: Complete this with the IP and PORT of the server
    r = remote("141.85.224.119", 1337)

def icc_enc_server(m, getp=False):
    """ 
    Encrypt a message m using our example cipher and known key as follows:
    c = icc_enc_server(m)

    Args:
    m should be a hexstring of 16 hex characters -- 8 bytes -- (m = L0 | R0)
    getp, if given and True, will return the result of the encryption
    at the intermediate point for a differential attack. 
    Note that in this case the output may not have 8 bytes.

    Return:
    The hexstring ciphertext c, with length 8 bytes (c = L3 | R3)
    """

    # The following is a proxy call to the actual implementation, which just
    # returns icc_enc(key, m, getp). The key is secret and stored only on the
    # server.
    if not LOCAL:
        r.readuntil(b"Input:")
        r.sendline(b'1' if not getp else b'2')
        r.readuntil(b'Plaintext:')
        r.sendline(m.encode())
        return r.readline().decode('utf-8').strip()

    return icc_enc(key, m, getp)


def icc_dec_server(c, getp=False):
    """
    Decrypt a ciphertext c in ECB mode using our example cipher and known key as follows:
    m = icc_dec(c)

    Args:
    c should be a hexstring of 16 hex characters -- 8 bytes -- (c = L0 | R0)
    getp, if given and True, will return the result of the encryption
    at the intermediate point for a differential attack.

    Return:
    The hexstring message m, with length 8 bytes (m = L0 | R0)
    """

    # The following is a proxy call to the actual implementation, which just
    # returns icc_dec(key, c, getp). The key is secret and stored only on the
    # server.
    if not LOCAL:
        r.readuntil(b"Input:")
        r.sendline(b'3' if not getp else b'4')
        r.readuntil(b'Ciphertext:')
        r.sendline(c.encode())
        return r.readline().decode('utf-8').strip()

    return icc_dec(key, c, getp)
