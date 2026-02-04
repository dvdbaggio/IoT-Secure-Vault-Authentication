def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))