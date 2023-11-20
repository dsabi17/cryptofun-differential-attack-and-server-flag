def _chunks(string, chunk_size):
    for i in range(0, len(string), chunk_size):
        yield string[i:i+chunk_size]


def _hex(x):
    return format(x, '02x')


def strxor(a, b):  # xor two strings (trims the longer input)
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])


def hexxor(a, b):  # xor two hex strings (trims the longer input)
    return ''.join(_hex(int(x, 16) ^ int(y, 16)) for (x, y) in zip(_chunks(a, 2), _chunks(b, 2)))


def bitxor(a, b):  # xor two bit strings (trims the longer input)
    return "".join([str(int(x) ^ int(y)) for (x, y) in zip(a, b)])


def str2bin(ss):
    """
      Transform a string (e.g. 'Hello') into a string of bits
    """
    bs = ''
    for c in ss:
        bs = bs + bin(ord(c))[2:].zfill(8)
    return bs


def str2hex(ss):
    """
      Transform a string (e.g. 'Hello') into a hex string
    """
    bs = str2bin(ss)
    hs = bin2hex(bs)
    return hs


def hex2bin(hs):
    """
      Transform a hex string (e.g. 'a2') into a string of bits (e.g.10100010)
    """
    bs = ''
    for c in hs:
        bs = bs + bin(int(c, 16))[2:].zfill(4)
    return bs


def bin2hex(bs):
    """
      Transform a bit string into a hex string
    """
    return hex(int(bs, 2))[2:]


def byte2bin(bval):
    """
      Transform a byte (8-bit) value into a bitstring
    """
    return bin(bval)[2:].zfill(8)


def str2int(ss):
    """
      Transform a string (e.g. 'Hello') into a (long) integer by converting
      first to a bitstream
    """
    bs = str2bin(ss)
    li = int(bs, 2)
    return li


def int2hexstring(bval):
    """
      Transform an int value into a hexstring (even number of characters)
    """
    hs = hex(bval)[2:]
    lh = len(hs)
    return hs.zfill(lh + lh % 2)


def hex2str(hs):
    """
      Transform a hex string into an ASCII string
    """
    return ''.join(chr(int(x, 16)) for x in _chunks(hs, 2))
